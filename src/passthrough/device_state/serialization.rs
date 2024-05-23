// Copyright 2024 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Serialization functionality (i.e. what happens in `SerializableFileSystem::serialize()`): Take
/// information that we have collected during preserialization and turn it into actually
/// serializable structs ('serialized' module), which are then turned into a plain vector of bytes.
use crate::fuse;
use crate::passthrough::device_state::preserialization::{self, HandleMigrationInfo};
use crate::passthrough::device_state::serialized;
use crate::passthrough::inode_store::InodeData;
use crate::passthrough::{self, Handle, HandleData, PassthroughFs};
use crate::util::other_io_error;
use std::convert::TryFrom;
use std::io;
use std::sync::atomic::Ordering;

impl TryFrom<serialized::PassthroughFs> for Vec<u8> {
    type Error = io::Error;

    /// Root of serialization: Turn the final `serialized::PassthroughFs` struct into plain bytes
    fn try_from(state: serialized::PassthroughFs) -> io::Result<Self> {
        postcard::to_stdvec(&state).map_err(other_io_error)
    }
}

impl TryFrom<&PassthroughFs> for serialized::PassthroughFsV1 {
    type Error = io::Error;

    /// Serialize `fs`, assuming it has been prepared for serialization (i.e. all inodes must have
    /// their migration info set)
    fn try_from(fs: &PassthroughFs) -> io::Result<Self> {
        let handles_map = fs.handles.read().unwrap();

        let inodes = fs
            .inodes
            .map(|inode| {
                inode
                    .as_ref()
                    .as_serialized(&fs.cfg)
                    .unwrap_or_else(|err| {
                        warn!(
                            "Failed to serialize inode {} (st_dev={}, mnt_id={}, st_ino={}): {}; marking as invalid",
                            inode.inode, inode.ids.dev, inode.ids.mnt_id, inode.ids.ino, err
                        );
                        serialized::Inode {
                            id: inode.inode,
                            refcount: inode.refcount.load(Ordering::Relaxed),
                            location: serialized::InodeLocation::Invalid,
                            file_handle: None,
                        }
                    })
            });

        let handles = handles_map
            .iter()
            .map(|(handle, data)| (*handle, data.as_ref()).into())
            .collect();

        Ok(serialized::PassthroughFsV1 {
            inodes,
            next_inode: fs.next_inode.load(Ordering::Relaxed),

            handles,
            next_handle: fs.next_handle.load(Ordering::Relaxed),

            negotiated_opts: fs.into(),
        })
    }
}

impl From<&PassthroughFs> for serialized::NegotiatedOpts {
    /// Serialize the options we have negotiated with the guest
    fn from(fs: &PassthroughFs) -> Self {
        serialized::NegotiatedOpts {
            writeback: fs.writeback.load(Ordering::Relaxed),
            announce_submounts: fs.announce_submounts.load(Ordering::Relaxed),
            posix_acl: fs.posix_acl.load(Ordering::Relaxed),
            sup_group_extension: fs.sup_group_extension.load(Ordering::Relaxed),
        }
    }
}

impl InodeData {
    /// Serialize an inode, which requires that its `migration_info` is set
    fn as_serialized(&self, fs_cfg: &passthrough::Config) -> io::Result<serialized::Inode> {
        let id = self.inode;
        let refcount = self.refcount.load(Ordering::Relaxed);

        // Note that we do not special-case invalid inodes here (`self.file_or_handle ==
        // FileOrHandle::Invalid(_)`), i.e. inodes that this instance failed to find on a prior
        // incoming migration.  We do not expect them to have migration info (we could not open
        // them, so we should not know where to find them), but if we do, there must be a reason
        // for it, so we might as well forward it to our destination.

        let migration_info_locked = self.migration_info.lock().unwrap();
        let migration_info = migration_info_locked
            .as_ref()
            .ok_or_else(|| other_io_error("Failed to reconstruct inode location"))?;

        // The root node (and only the root node) must have its special kind of placeholder info
        assert_eq!(
            (id == fuse::ROOT_ID),
            matches!(
                migration_info.location,
                preserialization::InodeLocation::RootNode
            )
        );

        // Serialize the information that tells the destination how to find this inode
        let location = migration_info.location.as_serialized()?;

        let file_handle = if fs_cfg.migration_verify_handles {
            // We could construct the file handle now, but we don't want to do I/O here.  It should
            // have been prepared in the preserialization phase.  If it is not, that's an internal
            // programming error.
            let handle = migration_info
                .file_handle
                .as_ref()
                .ok_or_else(|| other_io_error("No prepared file handle found"))?;
            Some(handle.clone())
        } else {
            None
        };

        Ok(serialized::Inode {
            id,
            refcount,
            location,
            file_handle,
        })
    }
}

impl preserialization::InodeLocation {
    /// Helper for serializing inodes: Turn their prepared `migration_info` into a
    /// `serialized::InodeLocation`
    fn as_serialized(&self) -> io::Result<serialized::InodeLocation> {
        Ok(match self {
            preserialization::InodeLocation::RootNode => serialized::InodeLocation::RootNode,

            preserialization::InodeLocation::Path { parent, filename } => {
                // Safe: We serialize everything before we will drop the serialized state (the
                // inode store), so the strong refcount in there will outlive this weak reference
                // (which means that the ID we get will remain valid until everything is
                // serialized, i.e. that parent node will be part of the serialized state)
                let parent = unsafe { parent.get_raw() };
                let filename = filename.clone();

                serialized::InodeLocation::Path { parent, filename }
            }
        })
    }
}

impl From<(Handle, &HandleData)> for serialized::Handle {
    /// Serialize a handle
    fn from(handle: (Handle, &HandleData)) -> Self {
        // Note that we will happily process invalid handles here (`handle.1.file ==
        // HandleDataFile::Invalid(_)`), i.e. handles that this instance failed to open on a prior
        // incoming migration.  A handle is identified by the inode to which it belongs, and
        // instructions on how to open that inode (e.g. `open()` flags).  If this instance failed
        // to open the inode in this way (on in-migration), that does not prevent us from
        // forwarding the same information to the next destination (on out-migration), and thus
        // allow it to re-try.

        let source = (&handle.1.migration_info).into();
        serialized::Handle {
            id: handle.0,
            inode: handle.1.inode,
            source,
        }
    }
}

impl From<&HandleMigrationInfo> for serialized::HandleSource {
    /// Helper for serializing handles: Turn their prepared `migration_info` into a
    /// `serialized::HandleSource`
    fn from(repr: &HandleMigrationInfo) -> Self {
        match repr {
            HandleMigrationInfo::OpenInode { flags } => {
                serialized::HandleSource::OpenInode { flags: *flags }
            }
        }
    }
}
