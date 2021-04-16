// Copyright 2021 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::passthrough::stat::statx;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::RwLock;

const MAX_HANDLE_SZ: usize = 128;

/**
 * Creating a file handle only returns a mount ID; opening a file handle requires an open fd on the
 * respective mount.  This is a type in which we can store fds that we know are associated with a
 * given mount ID, so that when opening a handle we can look it up.
 */
#[derive(Default)]
pub struct MountFds {
    map: RwLock<HashMap<u64, File>>,
}

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
#[repr(C)]
struct CFileHandle {
    handle_bytes: libc::c_uint,
    handle_type: libc::c_int,
    f_handle: [libc::c_char; MAX_HANDLE_SZ],
}

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct FileHandle {
    mnt_id: u64,
    handle: CFileHandle,
}

extern "C" {
    fn name_to_handle_at(
        dirfd: libc::c_int,
        pathname: *const libc::c_char,
        file_handle: *mut CFileHandle,
        mount_id: *mut libc::c_int,
        flags: libc::c_int,
    ) -> libc::c_int;

    // Technically `file_handle` should be a `mut` pointer, but `open_by_handle_at()` is specified
    // not to change it, so we can declare it `const`.
    fn open_by_handle_at(
        mount_fd: libc::c_int,
        file_handle: *const CFileHandle,
        flags: libc::c_int,
    ) -> libc::c_int;
}

impl MountFds {
    pub fn new() -> Self {
        MountFds::default()
    }
}

impl FileHandle {
    /// Create a file handle for the given file.
    fn from_name_at(dir: &impl AsRawFd, path: &CStr) -> io::Result<Self> {
        let mut mount_id: libc::c_int = 0;
        let mut c_fh = CFileHandle {
            handle_bytes: MAX_HANDLE_SZ as libc::c_uint,
            handle_type: 0,
            f_handle: [0; MAX_HANDLE_SZ],
        };

        let ret = unsafe {
            name_to_handle_at(
                dir.as_raw_fd(),
                path.as_ptr(),
                &mut c_fh,
                &mut mount_id,
                libc::AT_EMPTY_PATH,
            )
        };
        if ret == 0 {
            Ok(FileHandle {
                mnt_id: mount_id as u64,
                handle: c_fh,
            })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /**
     * Create a file handle for the given file, and ensure that `mount_fds` contains a valid fd for
     * the mount the file is on (so that `handle.open_with_mount_fds()` will work).
     *
     * If `path` is empty, `reopen_dir` may be invoked to duplicate `dir` with custom
     * `libc::open()` flags.
     */
    pub fn from_name_at_with_mount_fds<F>(
        dir: &impl AsRawFd,
        path: &CStr,
        mount_fds: &MountFds,
        reopen_dir: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(RawFd, libc::c_int) -> io::Result<File>,
    {
        let handle = Self::from_name_at(dir, path)?;

        if !mount_fds.map.read().unwrap().contains_key(&handle.mnt_id) {
            let file = if path.to_bytes().is_empty() {
                // `open_by_handle_at()` needs a non-`O_PATH` fd, and `dir` may be `O_PATH`, so we
                // have to open a new fd here
                reopen_dir(
                    dir.as_raw_fd(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )?
            } else {
                // `openat(dir, path)` should give us a file on the mount
                let ret = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        path.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
                // `openat()` guarantees `ret` is a valid fd
                unsafe { File::from_raw_fd(ret) }
            };

            // Ensure that `file` refers to an inode with the mount ID we need
            if statx(&file, None)?.mnt_id != handle.mnt_id {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }

            mount_fds.map.write().unwrap().insert(handle.mnt_id, file);
        }

        Ok(handle)
    }

    /**
     * Open a file handle (low-level wrapper).
     *
     * `mount_fd` must be an open non-`O_PATH` file descriptor for an inode on the same mount as
     * the file to be opened, i.e. the mount given by `self.mnt_id`.
     */
    fn open(&self, mount_fd: &impl AsRawFd, flags: libc::c_int) -> io::Result<File> {
        let ret = unsafe { open_by_handle_at(mount_fd.as_raw_fd(), &self.handle, flags) };
        if ret >= 0 {
            // Safe because `open_by_handle_at()` guarantees this is a valid fd
            let file = unsafe { File::from_raw_fd(ret) };
            Ok(file)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /**
     * Open a file handle, using the given `mount_fds` hash map.
     *
     * Look up `self.mnt_id` in `mount_fds`, and pass the result to `self.open()`.
     */
    pub fn open_with_mount_fds(
        &self,
        mount_fds: &MountFds,
        flags: libc::c_int,
    ) -> io::Result<File> {
        let mount_fds_locked = mount_fds.map.read();

        let mount_file = mount_fds_locked
            .as_ref()
            .unwrap()
            .get(&self.mnt_id)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))?;

        self.open(mount_file, flags)
    }
}
