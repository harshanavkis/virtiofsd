// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use crate::passthrough::file_handle::{FileHandle, FileOrHandle};
use crate::passthrough::stat::MountId;
use crate::passthrough::util::{ebadf, is_safe_inode, reopen_fd_through_proc};
use crate::util::other_io_error;
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub type Inode = u64;

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct InodeIds {
    pub ino: libc::ino64_t,
    pub dev: libc::dev_t,
    pub mnt_id: MountId,
}

pub struct InodeData {
    pub inode: Inode,
    // Most of these aren't actually files but ¯\_(ツ)_/¯.
    pub file_or_handle: FileOrHandle,
    pub refcount: AtomicU64,

    // Used as key in the `InodeStoreInner::by_ids` map.
    pub ids: InodeIds,

    // File type and mode
    pub mode: u32,
}

/**
 * Represents the file associated with an inode (`InodeData`).
 *
 * When obtaining such a file, it may either be a new file (the `Owned` variant), in which case the
 * object's lifetime is static, or it may reference `InodeData.file` (the `Ref` variant), in which
 * case the object's lifetime is that of the respective `InodeData` object.
 */
pub enum InodeFile<'inode_lifetime> {
    Owned(File),
    Ref(&'inode_lifetime File),
}

#[derive(Default)]
struct InodeStoreInner {
    data: BTreeMap<Inode, Arc<InodeData>>,
    by_ids: BTreeMap<InodeIds, Inode>,
    by_handle: BTreeMap<FileHandle, Inode>,
}

#[derive(Default)]
pub struct InodeStore {
    inner: Arc<RwLock<InodeStoreInner>>,
}

impl<'a> InodeData {
    /// Get an `O_PATH` file for this inode
    pub fn get_file(&'a self) -> io::Result<InodeFile<'a>> {
        match &self.file_or_handle {
            FileOrHandle::File(f) => Ok(InodeFile::Ref(f)),
            FileOrHandle::Handle(h) => {
                let file = h.open(libc::O_PATH)?;
                Ok(InodeFile::Owned(file))
            }
        }
    }

    /// Open this inode with the given flags
    /// (always returns a new (i.e. `Owned`) file, hence the static lifetime)
    pub fn open_file(
        &self,
        flags: libc::c_int,
        proc_self_fd: &File,
    ) -> io::Result<InodeFile<'static>> {
        if !is_safe_inode(self.mode) {
            return Err(ebadf());
        }

        match &self.file_or_handle {
            FileOrHandle::File(f) => {
                let new_file = reopen_fd_through_proc(f, flags, proc_self_fd)?;
                Ok(InodeFile::Owned(new_file))
            }
            FileOrHandle::Handle(h) => {
                let new_file = h.open(flags)?;
                Ok(InodeFile::Owned(new_file))
            }
        }
    }
}

impl InodeFile<'_> {
    /// Create a standalone `File` object
    pub fn into_file(self) -> io::Result<File> {
        match self {
            Self::Owned(file) => Ok(file),
            Self::Ref(file_ref) => file_ref.try_clone(),
        }
    }
}

impl AsRawFd for InodeFile<'_> {
    /// Return a file descriptor for this file
    /// Note: This fd is only valid as long as the `InodeFile` exists.
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Owned(file) => file.as_raw_fd(),
            Self::Ref(file_ref) => file_ref.as_raw_fd(),
        }
    }
}

impl InodeStoreInner {
    fn insert(&mut self, data: Arc<InodeData>) {
        self.by_ids.insert(data.ids, data.inode);
        if let FileOrHandle::Handle(handle) = &data.file_or_handle {
            self.by_handle.insert(handle.inner().clone(), data.inode);
        }
        self.data.insert(data.inode, data);
    }

    fn remove(&mut self, inode: Inode) -> Option<Arc<InodeData>> {
        let data = self.data.remove(&inode);
        if let Some(data) = data.as_ref() {
            if let FileOrHandle::Handle(handle) = &data.file_or_handle {
                self.by_handle.remove(handle.inner());
            }
            self.by_ids.remove(&data.ids);
        }
        data
    }

    fn clear(&mut self) {
        self.data.clear();
        self.by_handle.clear();
        self.by_ids.clear();
    }

    fn get(&self, inode: Inode) -> Option<&Arc<InodeData>> {
        self.data.get(&inode)
    }

    fn get_by_ids(&self, ids: &InodeIds) -> Option<&Arc<InodeData>> {
        self.inode_by_ids(ids).map(|inode| self.get(inode).unwrap())
    }

    fn get_by_handle(&self, handle: &FileHandle) -> Option<&Arc<InodeData>> {
        self.inode_by_handle(handle)
            .map(|inode| self.get(inode).unwrap())
    }

    fn contains(&self, inode: Inode) -> bool {
        self.data.contains_key(&inode)
    }

    fn inode_by_ids(&self, ids: &InodeIds) -> Option<Inode> {
        self.by_ids.get(ids).copied()
    }

    fn inode_by_handle(&self, handle: &FileHandle) -> Option<Inode> {
        self.by_handle.get(handle).copied()
    }

    /// Decrement the refcount of the given `inode` ID, and remove it from the store when it
    /// reaches 0
    fn forget_one(&mut self, inode: Inode, count: u64) {
        if let Some(data) = self.get(inode) {
            // Having a mutable reference on `self` prevents concurrent lookups from incrementing
            // the refcount but there is the possibility that a previous lookup already acquired a
            // reference to the inode data and is in the process of updating the refcount so we
            // need to loop here until we can decrement successfully.
            loop {
                let refcount = data.refcount.load(Ordering::Relaxed);

                // Saturating sub because it doesn't make sense for a refcount to go below zero and
                // we don't want misbehaving clients to cause integer overflow.
                let new_count = refcount.saturating_sub(count);

                // We don't need any stronger ordering, because the refcount itself doesn't protect
                // any data.
                if data.refcount.compare_exchange(
                    refcount,
                    new_count,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) == Ok(refcount)
                {
                    if new_count == 0 {
                        // We just removed the last refcount for this inode. There's no need for an
                        // acquire fence here because we have a mutable reference on `self`. So
                        // there's is no other release store for us to synchronize with before
                        // deleting the entry.
                        self.remove(inode);
                    }
                    break;
                }
            }
        }
    }
}

impl InodeStore {
    pub fn get(&self, inode: Inode) -> Option<Arc<InodeData>> {
        self.inner.read().unwrap().get(inode).cloned()
    }

    pub fn get_by_ids(&self, ids: &InodeIds) -> Option<Arc<InodeData>> {
        self.inner.read().unwrap().get_by_ids(ids).cloned()
    }

    pub fn get_by_handle(&self, handle: &FileHandle) -> Option<Arc<InodeData>> {
        self.inner.read().unwrap().get_by_handle(handle).cloned()
    }

    pub fn inode_by_ids(&self, ids: &InodeIds) -> Option<Inode> {
        self.inner.read().unwrap().inode_by_ids(ids)
    }

    pub fn inode_by_handle(&self, handle: &FileHandle) -> Option<Inode> {
        self.inner.read().unwrap().inode_by_handle(handle)
    }

    /// Attempt to get an inode from `inodes` and create a strong reference to it, i.e. increment
    /// its refcount.  Return that reference on success, and an error on failure.
    /// Reasons for failure can be that the inode isn't in the map or that the refcount is zero.
    /// This function will never increment a refcount that's already zero.
    pub fn claim_inode(&self, handle: Option<&FileHandle>, ids: &InodeIds) -> io::Result<Inode> {
        self.do_claim_inode(&self.inner.read().unwrap(), handle, ids)
    }

    fn do_claim_inode<I: Deref<Target = InodeStoreInner>>(
        &self,
        inner: &I,
        handle: Option<&FileHandle>,
        ids: &InodeIds,
    ) -> io::Result<Inode> {
        let data = handle
            .and_then(|h| inner.get_by_handle(h))
            .or_else(|| {
                inner.get_by_ids(ids).filter(|data| {
                    // When we have to fall back to looking up an inode by its inode ID, ensure
                    // that we hit an entry that has a valid file descriptor.  Having an FD open
                    // means that the inode cannot really be deleted until the FD is closed, so
                    // that the inode ID remains valid until we evict the `InodeData`.  With no FD
                    // open (and just a file handle), the inode can be deleted while we still have
                    // our `InodeData`, and so the inode ID may be reused by a completely different
                    // new inode.  Such inodes must be looked up by file handle, because this
                    // handle contains a generation ID to differentiate between the old and the new
                    // inode.
                    matches!(data.file_or_handle, FileOrHandle::File(_))
                })
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Cannot take strong reference to inode by handle or IDs, not found".to_string(),
                )
            })?;

        Ok(data.inode)
    }

    /// Check whether a matching inode is already present (see `claim_inode`), and if so, return
    /// that inode and drop `inode_data`.
    /// Otherwise, insert `inode_data`, and return a strong reference to it.  `inode_data.refcount`
    /// is ignored; the returned strong reference is the only one that can exist, so the refcount
    /// is hard-set to 1.
    pub fn get_or_insert(&self, mut inode_data: InodeData) -> io::Result<Inode> {
        let mut inner = self.inner.write().unwrap();
        let handle = match &inode_data.file_or_handle {
            FileOrHandle::File(_) => None,
            FileOrHandle::Handle(handle) => Some(handle.inner()),
        };
        if let Ok(inode) = self.do_claim_inode(&inner, handle, &inode_data.ids) {
            return Ok(inode);
        }
        if inner.contains(inode_data.inode) {
            return Err(other_io_error(format!(
                "Double-use of FUSE inode ID {}",
                inode_data.inode
            )));
        }

        // Safe because we have the only reference
        inode_data.refcount = AtomicU64::new(1);
        let inode = inode_data.inode;
        inner.insert(Arc::new(inode_data));

        Ok(inode)
    }

    /// Insert `inode_data` into the inode store regardless of whether a matching inode already
    /// exists.  However, if the given inode ID already exists, return an error and drop
    /// `inode_data.`
    pub fn new_inode(&self, inode_data: InodeData) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        if inner.contains(inode_data.inode) {
            return Err(other_io_error(format!(
                "Double-use of FUSE inode ID {}",
                inode_data.inode
            )));
        }
        inner.insert(Arc::new(inode_data));
        Ok(())
    }

    pub fn remove(&self, inode: Inode) {
        self.inner.write().unwrap().remove(inode);
    }

    pub fn forget_one(&self, inode: Inode, count: u64) {
        self.inner.write().unwrap().forget_one(inode, count);
    }

    pub fn forget_many<I: IntoIterator<Item = (Inode, u64)>>(&self, inodes: I) {
        let mut inner = self.inner.write().unwrap();
        for (inode, count) in inodes {
            inner.forget_one(inode, count);
        }
    }

    pub fn clear(&self) {
        self.inner.write().unwrap().clear();
    }
}
