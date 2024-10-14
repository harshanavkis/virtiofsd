// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::filesystem::{
    Context, DirEntry, DirectoryIterator, Entry, Extensions, FileSystem, GetxattrReply,
    ListxattrReply, SecContext, SerializableFileSystem,
};
use crate::fuse::*;
use crate::passthrough::util::einval;
use crate::{Error, Result};
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{size_of, MaybeUninit};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use vm_memory::ByteValued;
use vsock::VsockStream;

const FUSE_BUFFER_HEADER_SIZE: u32 = 0x1000;
const MAX_BUFFER_SIZE: u32 = 1 << 20;
const DIRENT_PADDING: [u8; 8] = [0; 8];

pub struct VsockFuseServer<F: FileSystem + Sync> {
    fs: F,
    options: AtomicU64,
}

impl<F: FileSystem + Sync> VsockFuseServer<F> {
    pub fn new(fs: F) -> VsockFuseServer<F> {
        VsockFuseServer {
            fs,
            options: AtomicU64::new(FsOptions::empty().bits()),
        }
    }

    fn read_obj<T: ByteValued>(&mut self, vsock_stream: &mut VsockStream) -> io::Result<T> {
        let mut obj = MaybeUninit::<T>::uninit();

        // Safe because `MaybeUninit` guarantees that the pointer is valid for
        // `size_of::<T>()` bytes.
        let buf = unsafe {
            ::std::slice::from_raw_parts_mut(obj.as_mut_ptr() as *mut u8, size_of::<T>())
        };

        vsock_stream.read_exact(buf)?;

        // Safe because any type that implements `ByteValued` can be considered initialized
        // even if it is filled with random data.
        Ok(unsafe { obj.assume_init() })
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn handle_message(&mut self, vsock_stream: &mut VsockStream) -> Result<usize> {
        let in_header: InHeader = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        if in_header.len > (MAX_BUFFER_SIZE + FUSE_BUFFER_HEADER_SIZE) {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                vsock_stream,
            );
        }

        if let Ok(opcode) = Opcode::try_from(in_header.opcode) {
            debug!(
                "Received request: opcode={:?} ({}), inode={}, unique={}, pid={}",
                opcode, in_header.opcode, in_header.nodeid, in_header.unique, in_header.pid
            );
            match opcode {
                Opcode::Lookup => self.lookup(in_header, vsock_stream),
                Opcode::Forget => self.forget(in_header, vsock_stream), // No reply.
                Opcode::Getattr => self.getattr(in_header, vsock_stream),
                Opcode::Setattr => self.setattr(in_header, vsock_stream),
                Opcode::Readlink => self.readlink(in_header, vsock_stream),
                Opcode::Symlink => self.symlink(in_header, vsock_stream),
                Opcode::Mknod => self.mknod(in_header, vsock_stream),
                Opcode::Mkdir => self.mkdir(in_header, vsock_stream),
                Opcode::Unlink => self.unlink(in_header, vsock_stream),
                Opcode::Rmdir => self.rmdir(in_header, vsock_stream),
                Opcode::Rename => self.rename(in_header, vsock_stream),
                Opcode::Link => self.link(in_header, vsock_stream),
                Opcode::Open => self.open(in_header, vsock_stream),
                Opcode::Read => self.read(in_header, vsock_stream),
                Opcode::Write => self.write(in_header, vsock_stream),
                Opcode::Statfs => self.statfs(in_header, vsock_stream),
                Opcode::Release => self.release(in_header, vsock_stream),
                Opcode::Fsync => self.fsync(in_header, vsock_stream),
                Opcode::Setxattr => self.setxattr(in_header, vsock_stream),
                Opcode::Getxattr => self.getxattr(in_header, vsock_stream),
                Opcode::Listxattr => self.listxattr(in_header, vsock_stream),
                Opcode::Removexattr => self.removexattr(in_header, vsock_stream),
                Opcode::Flush => self.flush(in_header, vsock_stream),
                Opcode::Init => self.init(in_header, vsock_stream),
                Opcode::Opendir => self.opendir(in_header, vsock_stream),
                Opcode::Readdir => self.readdir(in_header, vsock_stream),
                Opcode::Releasedir => self.releasedir(in_header, vsock_stream),
                Opcode::Fsyncdir => self.fsyncdir(in_header, vsock_stream),
                Opcode::Getlk => self.getlk(in_header, vsock_stream),
                Opcode::Setlk => self.setlk(in_header, vsock_stream),
                Opcode::Setlkw => self.setlkw(in_header, vsock_stream),
                Opcode::Access => self.access(in_header, vsock_stream),
                Opcode::Create => self.create(in_header, vsock_stream),
                Opcode::Interrupt => Ok(self.interrupt(in_header)),
                Opcode::Bmap => self.bmap(in_header, vsock_stream),
                Opcode::Destroy => Ok(self.destroy()),
                Opcode::Ioctl => self.ioctl(in_header, vsock_stream),
                Opcode::Poll => self.poll(in_header, vsock_stream),
                Opcode::NotifyReply => self.notify_reply(in_header, vsock_stream),
                Opcode::BatchForget => self.batch_forget(in_header, vsock_stream),
                Opcode::Fallocate => self.fallocate(in_header, vsock_stream),
                Opcode::Rename2 => self.rename2(in_header, vsock_stream),
                Opcode::Lseek => self.lseek(in_header, vsock_stream),
                Opcode::CopyFileRange => self.copyfilerange(in_header, vsock_stream),
                Opcode::Syncfs => self.syncfs(in_header, vsock_stream),
                Opcode::TmpFile => self.tmpfile(in_header, vsock_stream),
                _ => Err(Error::MissingExtension),
            }
        } else {
            debug!(
                "Received unknown request: opcode={}, inode={}",
                in_header.opcode, in_header.nodeid
            );
            reply_error(
                io::Error::from_raw_os_error(libc::ENOSYS),
                in_header.unique,
                vsock_stream,
            )
        }
    }

    fn lookup(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0u8; namelen];

        vsock_stream
            .read_exact(&mut buf)
            .map_err(Error::DecodeMessage)?;

        let name = bytes_to_cstr(buf.as_ref())?;

        match self
            .fs
            .lookup(Context::from(in_header), in_header.nodeid.into(), name)
        {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn forget(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let ForgetIn { nlookup } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        self.fs
            .forget(Context::from(in_header), in_header.nodeid.into(), nlookup);

        // There is no reply for forget messages.
        Ok(0)
    }

    fn getattr(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let GetattrIn { flags, fh, .. } =
            self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let handle = if (flags & GETATTR_FH) != 0 {
            Some(fh.into())
        } else {
            None
        };

        match self
            .fs
            .getattr(Context::from(in_header), in_header.nodeid.into(), handle)
        {
            Ok((st, timeout)) => {
                let out = AttrOut {
                    attr_valid: timeout.as_secs(),
                    attr_valid_nsec: timeout.subsec_nanos(),
                    dummy: 0,
                    attr: st.into(),
                };
                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn setattr(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let setattr_in: SetattrIn = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let handle = if setattr_in.valid & FATTR_FH != 0 {
            Some(setattr_in.fh.into())
        } else {
            None
        };

        let valid = SetattrValid::from_bits_truncate(setattr_in.valid);

        let st: libc::stat64 = setattr_in.into();

        match self.fs.setattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            st,
            handle,
            valid,
        ) {
            Ok((st, timeout)) => {
                let out = AttrOut {
                    attr_valid: timeout.as_secs(),
                    attr_valid_nsec: timeout.subsec_nanos(),
                    dummy: 0,
                    attr: st.into(),
                };
                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn readlink(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        match self
            .fs
            .readlink(Context::from(in_header), in_header.nodeid.into())
        {
            Ok(linkname) => {
                // We need to disambiguate the option type here even though it is `None`.
                reply_ok(None::<u8>, Some(&linkname), in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn symlink(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        // Unfortunately the name and linkname are encoded one after another and
        // separated by a nul character.
        let len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; len];

        vsock_stream
            .read_exact(&mut buf)
            .map_err(Error::DecodeMessage)?;

        let mut components = buf.split_inclusive(|c| *c == b'\0');

        let name = components.next().ok_or(Error::MissingParameter)?;
        let linkname = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len() + linkname.len(), buf.as_slice())?;

        match self.fs.symlink(
            Context::from(in_header),
            bytes_to_cstr(linkname)?,
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            extensions,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn mknod(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let MknodIn {
            mode, rdev, umask, ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let remaining_len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<MknodIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; remaining_len];

        vsock_stream
            .read_exact(&mut buf)
            .map_err(Error::DecodeMessage)?;
        let mut components = buf.split_inclusive(|c| *c == b'\0');
        let name = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len(), buf.as_slice())?;

        match self.fs.mknod(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            mode,
            rdev,
            umask,
            extensions,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn mkdir(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let MkdirIn { mode, umask } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let remaining_len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<MkdirIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; remaining_len];

        vsock_stream
            .read_exact(&mut buf)
            .map_err(Error::DecodeMessage)?;
        let mut components = buf.split_inclusive(|c| *c == b'\0');
        let name = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len(), buf.as_slice())?;

        match self.fs.mkdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            mode,
            umask,
            extensions,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn unlink(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        vsock_stream
            .read_exact(&mut name)
            .map_err(Error::DecodeMessage)?;

        match self.fs.unlink(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn rmdir(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        vsock_stream
            .read_exact(&mut name)
            .map_err(Error::DecodeMessage)?;

        match self.fs.rmdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn do_rename(
        &self,
        in_header: InHeader,
        msg_size: usize,
        newdir: u64,
        flags: u32,
        vsock_stream: &mut VsockStream,
    ) -> Result<usize> {
        let buflen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(msg_size))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; buflen];

        vsock_stream
            .read_exact(&mut buf)
            .map_err(Error::DecodeMessage)?;

        // We want to include the '\0' byte in the first slice.
        let split_pos = buf
            .iter()
            .position(|c| *c == b'\0')
            .map(|p| p + 1)
            .ok_or(Error::MissingParameter)?;

        let (oldname, newname) = buf.split_at(split_pos);

        match self.fs.rename(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(oldname)?,
            newdir.into(),
            bytes_to_cstr(newname)?,
            flags,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn rename(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let RenameIn { newdir } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        self.do_rename(in_header, size_of::<RenameIn>(), newdir, 0, vsock_stream)
    }

    fn rename2(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let Rename2In { newdir, flags, .. } =
            self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let flags =
            flags & (libc::RENAME_EXCHANGE | libc::RENAME_NOREPLACE | libc::RENAME_WHITEOUT);

        self.do_rename(
            in_header,
            size_of::<Rename2In>(),
            newdir,
            flags,
            vsock_stream,
        )
    }

    fn link(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let LinkIn { oldnodeid } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<LinkIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        vsock_stream
            .read_exact(&mut name)
            .map_err(Error::DecodeMessage)?;

        match self.fs.link(
            Context::from(in_header),
            oldnodeid.into(),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn open(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let OpenIn {
            flags, open_flags, ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let kill_priv = open_flags & OPEN_KILL_SUIDGID != 0;

        match self.fs.open(
            Context::from(in_header),
            in_header.nodeid.into(),
            kill_priv,
            flags,
        ) {
            Ok((handle, opts)) => {
                let out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn read(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let ReadIn {
            fh, offset, size, ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let mut read_buffer = vec![0; size as usize];

        match self.fs.read_vsock_version(
            in_header.nodeid.into(),
            fh.into(),
            &mut read_buffer,
            size,
            offset,
        ) {
            Ok(count) => {
                let out = OutHeader {
                    len: (size_of::<OutHeader>() + count) as u32,
                    error: 0,
                    unique: in_header.unique,
                };

                debug!("Replying OK, header: {:?}", out);
                vsock_stream
                    .write_all(out.as_slice())
                    .map_err(Error::EncodeMessage)?;

                debug!("Replying with data:");
                vsock_stream.write_all(&read_buffer).unwrap();
                Ok(out.len as usize)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn write(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let WriteIn {
            fh,
            offset,
            size,
            write_flags,
            ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let delayed_write = write_flags & WRITE_CACHE != 0;
        let kill_priv = write_flags & WRITE_KILL_PRIV != 0;

        debug!("Reading write data from stream");
        let mut write_buffer = vec![0u8; size as usize];
        vsock_stream.read_exact(&mut write_buffer).unwrap();

        match self.fs.write_vsock_version(
            in_header.nodeid.into(),
            fh.into(),
            &write_buffer,
            size,
            offset,
            delayed_write,
            kill_priv,
        ) {
            Ok(count) => {
                let out = WriteOut {
                    size: count as u32,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn statfs(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        match self
            .fs
            .statfs(Context::from(in_header), in_header.nodeid.into())
        {
            Ok(st) => reply_ok(
                Some(Kstatfs::from(st)),
                None,
                in_header.unique,
                vsock_stream,
            ),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn release(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let ReleaseIn {
            fh,
            flags,
            release_flags,
            lock_owner,
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let flush = release_flags & RELEASE_FLUSH != 0;
        let flock_release = release_flags & RELEASE_FLOCK_UNLOCK != 0;
        let lock_owner = if flush || flock_release {
            Some(lock_owner)
        } else {
            None
        };

        match self.fs.release(
            Context::from(in_header),
            in_header.nodeid.into(),
            flags,
            fh.into(),
            flush,
            flock_release,
            lock_owner,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn fsync(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let FsyncIn {
            fh, fsync_flags, ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;
        let datasync = fsync_flags & 0x1 != 0;

        match self.fs.fsync(
            Context::from(in_header),
            in_header.nodeid.into(),
            datasync,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn setxattr(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));
        let (
            SetxattrIn {
                size,
                flags,
                setxattr_flags,
                ..
            },
            setxattrin_size,
        ) = if options.contains(FsOptions::SETXATTR_EXT) {
            (
                self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?,
                size_of::<SetxattrIn>(),
            )
        } else {
            let SetxattrInCompat { size, flags } =
                self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;
            (
                SetxattrIn {
                    size,
                    flags,
                    setxattr_flags: 0,
                    padding: 0,
                },
                size_of::<SetxattrInCompat>(),
            )
        };

        // The name and value and encoded one after another and separated by a '\0' character.
        let len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(setxattrin_size))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; len];

        vsock_stream
            .read_exact(&mut buf)
            .map_err(Error::DecodeMessage)?;

        // We want to include the '\0' byte in the first slice.
        let split_pos = buf
            .iter()
            .position(|c| *c == b'\0')
            .map(|p| p + 1)
            .ok_or(Error::MissingParameter)?;

        let (name, value) = buf.split_at(split_pos);

        if size != value.len() as u32 {
            return Err(Error::InvalidXattrSize((size, value.len())));
        }

        match self.fs.setxattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            value,
            flags,
            SetxattrFlags::from_bits_truncate(setxattr_flags),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn getxattr(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let GetxattrIn { size, .. } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<GetxattrIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        vsock_stream
            .read_exact(&mut name)
            .map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                vsock_stream,
            );
        }

        match self.fs.getxattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
            size,
        ) {
            Ok(GetxattrReply::Value(val)) => {
                reply_ok(None::<u8>, Some(&val), in_header.unique, vsock_stream)
            }
            Ok(GetxattrReply::Count(count)) => {
                let out = GetxattrOut {
                    size: count,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn listxattr(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let GetxattrIn { size, .. } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                vsock_stream,
            );
        }

        match self
            .fs
            .listxattr(Context::from(in_header), in_header.nodeid.into(), size)
        {
            Ok(ListxattrReply::Names(val)) => {
                reply_ok(None::<u8>, Some(&val), in_header.unique, vsock_stream)
            }
            Ok(ListxattrReply::Count(count)) => {
                let out = GetxattrOut {
                    size: count,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn removexattr(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0; namelen];

        vsock_stream
            .read_exact(&mut buf)
            .map_err(Error::DecodeMessage)?;

        let name = bytes_to_cstr(&buf)?;

        match self
            .fs
            .removexattr(Context::from(in_header), in_header.nodeid.into(), name)
        {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn flush(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let FlushIn { fh, lock_owner, .. } =
            self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        match self.fs.flush(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            lock_owner,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn init(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let InitInCompat {
            major,
            minor,
            max_readahead,
            flags,
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let options = FsOptions::from_bits_truncate(flags as u64);

        let InitInExt { flags2, .. } = if options.contains(FsOptions::INIT_EXT) {
            self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?
        } else {
            InitInExt::default()
        };

        if major < KERNEL_VERSION {
            error!("Unsupported fuse protocol version: {}.{}", major, minor);
            return reply_error(
                io::Error::from_raw_os_error(libc::EPROTO),
                in_header.unique,
                vsock_stream,
            );
        }

        if major > KERNEL_VERSION {
            // Wait for the kernel to reply back with a 7.X version.
            let out = InitOut {
                major: KERNEL_VERSION,
                minor: KERNEL_MINOR_VERSION,
                ..Default::default()
            };

            return reply_ok(Some(out), None, in_header.unique, vsock_stream);
        }

        if minor < MIN_KERNEL_MINOR_VERSION {
            error!(
                "Unsupported fuse protocol minor version: {}.{}",
                major, minor
            );
            return reply_error(
                io::Error::from_raw_os_error(libc::EPROTO),
                in_header.unique,
                vsock_stream,
            );
        }

        // These fuse features are supported by this server by default.
        let supported = FsOptions::ASYNC_READ
            | FsOptions::PARALLEL_DIROPS
            | FsOptions::BIG_WRITES
            | FsOptions::AUTO_INVAL_DATA
            | FsOptions::ASYNC_DIO
            | FsOptions::HAS_IOCTL_DIR
            | FsOptions::ATOMIC_O_TRUNC
            | FsOptions::MAX_PAGES
            | FsOptions::SUBMOUNTS
            | FsOptions::INIT_EXT
            | FsOptions::CREATE_SUPP_GROUP;

        let flags_64 = ((flags2 as u64) << 32) | (flags as u64);
        let capable = FsOptions::from_bits_truncate(flags_64);

        let page_size: u32 = unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() };
        let max_pages = ((MAX_BUFFER_SIZE - 1) / page_size) + 1;

        match self.fs.init(capable) {
            Ok(want) => {
                let enabled = (capable & (want | supported)).bits();
                self.options.store(enabled, Ordering::Relaxed);

                let out = InitOut {
                    major: KERNEL_VERSION,
                    minor: KERNEL_MINOR_VERSION,
                    max_readahead,
                    flags: enabled as u32,
                    max_background: u16::MAX,
                    congestion_threshold: (u16::MAX / 4) * 3,
                    max_write: MAX_BUFFER_SIZE,
                    time_gran: 1, // nanoseconds
                    max_pages: max_pages.try_into().unwrap(),
                    map_alignment: 0,
                    flags2: (enabled >> 32) as u32,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn opendir(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let OpenIn { flags, .. } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        match self
            .fs
            .opendir(Context::from(in_header), in_header.nodeid.into(), flags)
        {
            Ok((handle, opts)) => {
                let out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn readdir(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let ReadIn {
            fh, offset, size, ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                vsock_stream,
            );
        }

        let mut direent_buf = vec![0u8; size as usize];

        // Skip over enough bytes for the header.
        let unique = in_header.unique;
        let result = match self.fs.readdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            size,
            offset,
        ) {
            Ok(mut entries) => {
                let mut total_written = 0;
                let mut err = None;
                while let Some(dirent) = entries.next() {
                    let remaining = (size as usize).saturating_sub(total_written);
                    match add_dirent(&mut direent_buf, total_written, remaining, dirent, None) {
                        // No more space left in the buffer.
                        Ok(0) => break,
                        Ok(bytes_written) => {
                            total_written += bytes_written;
                        }
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
                if let Some(err) = err {
                    Err(err)
                } else {
                    Ok(total_written)
                }
            }
            Err(e) => Err(e),
        };

        match result {
            Ok(total_written) => reply_readdir(total_written, unique, vsock_stream),
            Err(e) => reply_error(e, unique, vsock_stream),
        }
    }

    fn releasedir(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let ReleaseIn { fh, flags, .. } =
            self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        match self.fs.releasedir(
            Context::from(in_header),
            in_header.nodeid.into(),
            flags,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn fsyncdir(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let FsyncIn {
            fh, fsync_flags, ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;
        let datasync = fsync_flags & 0x1 != 0;

        match self.fs.fsyncdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            datasync,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn getlk(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        if let Err(e) = self.fs.getlk() {
            reply_error(e, in_header.unique, vsock_stream)
        } else {
            Ok(0)
        }
    }

    fn setlk(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        if let Err(e) = self.fs.setlk() {
            reply_error(e, in_header.unique, vsock_stream)
        } else {
            Ok(0)
        }
    }

    fn setlkw(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        if let Err(e) = self.fs.setlkw() {
            reply_error(e, in_header.unique, vsock_stream)
        } else {
            Ok(0)
        }
    }

    fn access(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let AccessIn { mask, .. } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        match self
            .fs
            .access(Context::from(in_header), in_header.nodeid.into(), mask)
        {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn create(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let CreateIn {
            flags,
            mode,
            umask,
            open_flags,
            ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        let remaining_len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<CreateIn>()))
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0; remaining_len];

        vsock_stream
            .read_exact(&mut buf)
            .map_err(Error::DecodeMessage)?;
        let mut components = buf.split_inclusive(|c| *c == b'\0');
        let name = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len(), buf.as_slice())?;

        let kill_priv = open_flags & OPEN_KILL_SUIDGID != 0;

        match self.fs.create(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            mode,
            kill_priv,
            flags,
            umask,
            extensions,
        ) {
            Ok((entry, handle, opts)) => {
                let entry_out = EntryOut {
                    nodeid: entry.inode,
                    generation: entry.generation,
                    entry_valid: entry.entry_timeout.as_secs(),
                    attr_valid: entry.attr_timeout.as_secs(),
                    entry_valid_nsec: entry.entry_timeout.subsec_nanos(),
                    attr_valid_nsec: entry.attr_timeout.subsec_nanos(),
                    attr: Attr::with_flags(entry.attr, entry.attr_flags),
                };
                let open_out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                // Kind of a hack to write both structs.
                reply_ok(
                    Some(entry_out),
                    Some(open_out.as_slice()),
                    in_header.unique,
                    vsock_stream,
                )
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn interrupt(&self, _in_header: InHeader) -> usize {
        0
    }

    fn bmap(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        if let Err(e) = self.fs.bmap() {
            reply_error(e, in_header.unique, vsock_stream)
        } else {
            Ok(0)
        }
    }

    fn destroy(&self) -> usize {
        // No reply to this function.
        self.fs.destroy();
        self.options
            .store(FsOptions::empty().bits(), Ordering::Relaxed);

        0
    }

    fn ioctl(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        if let Err(e) = self.fs.ioctl() {
            reply_error(e, in_header.unique, vsock_stream)
        } else {
            Ok(0)
        }
    }

    fn poll(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        if let Err(e) = self.fs.poll() {
            reply_error(e, in_header.unique, vsock_stream)
        } else {
            Ok(0)
        }
    }

    fn notify_reply(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        if let Err(e) = self.fs.notify_reply() {
            reply_error(e, in_header.unique, vsock_stream)
        } else {
            Ok(0)
        }
    }

    fn batch_forget(
        &mut self,
        in_header: InHeader,
        vsock_stream: &mut VsockStream,
    ) -> Result<usize> {
        let BatchForgetIn { count, .. } =
            self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        if let Some(size) = (count as usize).checked_mul(size_of::<ForgetOne>()) {
            if size > MAX_BUFFER_SIZE as usize {
                return reply_error(
                    io::Error::from_raw_os_error(libc::ENOMEM),
                    in_header.unique,
                    vsock_stream,
                );
            }
        } else {
            return reply_error(
                io::Error::from_raw_os_error(libc::EOVERFLOW),
                in_header.unique,
                vsock_stream,
            );
        }

        let mut requests = Vec::with_capacity(count as usize);
        for _ in 0..count {
            requests.push(
                self.read_obj::<ForgetOne>(vsock_stream)
                    .map(|f| (f.nodeid.into(), f.nlookup))
                    .map_err(Error::DecodeMessage)?,
            );
        }

        self.fs.batch_forget(Context::from(in_header), requests);

        // No reply for forget messages.
        Ok(0)
    }

    fn fallocate(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let FallocateIn {
            fh,
            offset,
            length,
            mode,
            ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        match self.fs.fallocate(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            mode,
            offset,
            length,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn lseek(&mut self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let LseekIn {
            fh, offset, whence, ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        match self.fs.lseek(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            offset,
            whence,
        ) {
            Ok(offset) => {
                let out = LseekOut { offset };

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn copyfilerange(
        &mut self,
        in_header: InHeader,
        vsock_stream: &mut VsockStream,
    ) -> Result<usize> {
        let CopyfilerangeIn {
            fh_in,
            off_in,
            nodeid_out,
            fh_out,
            off_out,
            len,
            flags,
            ..
        } = self.read_obj(vsock_stream).map_err(Error::DecodeMessage)?;

        match self.fs.copyfilerange(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh_in.into(),
            off_in,
            nodeid_out.into(),
            fh_out.into(),
            off_out,
            len,
            flags,
        ) {
            Ok(count) => {
                let out = WriteOut {
                    size: count as u32,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, vsock_stream)
            }
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn syncfs(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        match self
            .fs
            .syncfs(Context::from(in_header), in_header.nodeid.into())
        {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, vsock_stream),
            Err(e) => reply_error(e, in_header.unique, vsock_stream),
        }
    }

    fn tmpfile(&self, in_header: InHeader, vsock_stream: &mut VsockStream) -> Result<usize> {
        let e = self
            .fs
            .tmpfile()
            .err()
            .unwrap_or_else(|| panic!("unsupported operation"));
        reply_error(e, in_header.unique, vsock_stream)
    }
}

impl<F: FileSystem + SerializableFileSystem + Sync> SerializableFileSystem for VsockFuseServer<F> {
    fn prepare_serialization(&self, cancel: Arc<AtomicBool>) {
        self.fs.prepare_serialization(cancel)
    }

    fn serialize(&self, state_pipe: File) -> io::Result<()> {
        self.fs.serialize(state_pipe)
    }

    fn deserialize_and_apply(&self, state_pipe: File) -> io::Result<()> {
        self.fs.deserialize_and_apply(state_pipe)
    }
}

fn reply_readdir(len: usize, unique: u64, vsock_stream: &mut VsockStream) -> Result<usize> {
    let out = OutHeader {
        len: (size_of::<OutHeader>() + len) as u32,
        error: 0,
        unique,
    };

    debug!("Replying OK, header: {:?}", out);
    vsock_stream
        .write_all(out.as_slice())
        .map_err(Error::EncodeMessage)?;
    vsock_stream.flush().map_err(Error::FlushMessage)?;
    Ok(out.len as usize)
}

fn reply_ok<T: ByteValued>(
    out: Option<T>,
    data: Option<&[u8]>,
    unique: u64,
    vsock_stream: &mut VsockStream,
) -> Result<usize> {
    let mut len = size_of::<OutHeader>();

    if out.is_some() {
        len += size_of::<T>();
    }

    if let Some(data) = data {
        len += data.len();
    }

    let header = OutHeader {
        len: len as u32,
        error: 0,
        unique,
    };

    debug!("Replying OK, header: {:?}", header);

    vsock_stream
        .write_all(header.as_slice())
        .map_err(Error::EncodeMessage)?;

    if let Some(out) = out {
        vsock_stream
            .write_all(out.as_slice())
            .map_err(Error::EncodeMessage)?;
    }

    if let Some(data) = data {
        vsock_stream.write_all(data).map_err(Error::EncodeMessage)?;
    }

    Ok(len)
}

fn strerror(error: i32) -> String {
    let mut err_desc: Vec<u8> = vec![0; 256];
    let buf_ptr = err_desc.as_mut_ptr() as *mut libc::c_char;

    // Safe because libc::strerror_r writes in err_desc at most err_desc.len() bytes
    unsafe {
        // We ignore the returned value since the two possible error values are:
        // EINVAL and ERANGE, in the former err_desc will be "Unknown error #"
        // and in the latter the message will be truncated to fit err_desc
        libc::strerror_r(error, buf_ptr, err_desc.len());
    }
    let err_desc = err_desc.split(|c| *c == b'\0').next().unwrap();
    String::from_utf8(err_desc.to_vec()).unwrap_or_else(|_| "".to_owned())
}

fn reply_error(e: io::Error, unique: u64, w: &mut VsockStream) -> Result<usize> {
    let header = OutHeader {
        len: size_of::<OutHeader>() as u32,
        error: -e.raw_os_error().unwrap_or(libc::EIO),
        unique,
    };

    debug!(
        "Replying ERROR, header: OutHeader {{ error: {} ({}), unique: {}, len: {} }}",
        header.error,
        strerror(-header.error),
        header.unique,
        header.len
    );

    w.write_all(header.as_slice())
        .map_err(Error::EncodeMessage)?;

    Ok(header.len as usize)
}

fn bytes_to_cstr(buf: &[u8]) -> Result<&CStr> {
    // Convert to a `CStr` first so that we can drop the '\0' byte at the end
    // and make sure there are no interior '\0' bytes.
    CStr::from_bytes_with_nul(buf).map_err(Error::InvalidCString)
}

fn add_dirent(
    dirent_buffer: &mut [u8],
    curr_offset: usize,
    max: usize,
    d: DirEntry,
    entry: Option<Entry>,
) -> io::Result<usize> {
    // Strip the trailing '\0'.
    let name = d.name.to_bytes();
    if name.len() > u32::MAX as usize {
        return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
    }

    let dirent_len = size_of::<Dirent>()
        .checked_add(name.len())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

    // Directory entries must be padded to 8-byte alignment.  If adding 7 causes
    // an overflow then this dirent cannot be properly padded.
    let padded_dirent_len = dirent_len
        .checked_add(7)
        .map(|l| l & !7)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

    let total_len = if entry.is_some() {
        padded_dirent_len
            .checked_add(size_of::<EntryOut>())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?
    } else {
        padded_dirent_len
    };

    let mut offset = curr_offset;
    let mut chunk_length;

    if max < total_len {
        Ok(0)
    } else {
        if let Some(entry) = entry {
            let entryout = EntryOut::from(entry);
            chunk_length = entryout.as_slice().len();
            dirent_buffer[offset..offset + chunk_length].copy_from_slice(entryout.as_slice());
            offset += chunk_length;
        }

        let dirent = Dirent {
            ino: d.ino,
            off: d.offset,
            namelen: name.len() as u32,
            type_: d.type_,
        };

        chunk_length = dirent.as_slice().len();
        dirent_buffer[offset..offset + chunk_length].copy_from_slice(dirent.as_slice());
        offset += chunk_length;

        chunk_length = name.len();
        dirent_buffer[offset..offset + chunk_length].copy_from_slice(name);
        offset += chunk_length;

        // We know that `dirent_len` <= `padded_dirent_len` due to the check above
        // so there's no need for checked arithmetic.
        let padding = padded_dirent_len - dirent_len;
        if padding > 0 {
            chunk_length = padding;
            dirent_buffer[offset..offset + chunk_length]
                .copy_from_slice(&DIRENT_PADDING[..padding]);
        }

        Ok(total_len)
    }
}

fn take_object<T: ByteValued>(data: &[u8]) -> Result<(T, &[u8])> {
    if data.len() < size_of::<T>() {
        return Err(Error::DecodeMessage(einval()));
    }

    let (object_bytes, remaining_bytes) = data.split_at(size_of::<T>());
    // SAFETY: `T` implements `ByteValued` that guarantees that it is safe to instantiate
    // `T` with random data.
    let object: T = unsafe { std::ptr::read_unaligned(object_bytes.as_ptr() as *const T) };
    Ok((object, remaining_bytes))
}

fn parse_security_context(nr_secctx: u32, data: &[u8]) -> Result<Option<SecContext>> {
    // Although the FUSE security context extension allows sending several security contexts,
    // currently the guest kernel only sends one.
    if nr_secctx > 1 {
        return Err(Error::DecodeMessage(einval()));
    } else if nr_secctx == 0 {
        // No security context sent. May be no LSM supports it.
        return Ok(None);
    }

    let (secctx, data) = take_object::<Secctx>(data)?;

    if secctx.size == 0 {
        return Err(Error::DecodeMessage(einval()));
    }

    let mut components = data.split_inclusive(|c| *c == b'\0');
    let secctx_name = components.next().ok_or(Error::MissingParameter)?;
    let (_, data) = data.split_at(secctx_name.len());

    if data.len() < secctx.size as usize {
        return Err(Error::DecodeMessage(einval()));
    }

    // Fuse client aligns the whole security context block to 64 byte
    // boundary. So it is possible that after actual security context
    // of secctx.size, there are some null padding bytes left. If
    // we ever parse more data after secctx, we will have to take those
    // null bytes into account. Total size (including null bytes) is
    // available in SecctxHeader->size.
    let (remaining, _) = data.split_at(secctx.size as usize);

    let fuse_secctx = SecContext {
        name: CString::from_vec_with_nul(secctx_name.to_vec()).map_err(Error::InvalidCString2)?,
        secctx: remaining.to_vec(),
    };

    Ok(Some(fuse_secctx))
}

fn parse_sup_groups(data: &[u8]) -> Result<u32> {
    let (group_header, group_id_bytes) = take_object::<SuppGroups>(data)?;

    // The FUSE extension allows sending several group IDs, but currently the guest
    // kernel only sends one.
    if group_header.nr_groups != 1 {
        return Err(Error::DecodeMessage(einval()));
    }

    let (gid, _) = take_object::<u32>(group_id_bytes)?;
    Ok(gid)
}

fn get_extensions(options: FsOptions, skip: usize, request_bytes: &[u8]) -> Result<Extensions> {
    let mut extensions = Extensions::default();

    if !(options.contains(FsOptions::SECURITY_CTX)
        || options.contains(FsOptions::CREATE_SUPP_GROUP))
    {
        return Ok(extensions);
    }

    // It's not guaranty to receive an extension even if it's supported by the guest kernel
    if request_bytes.len() < skip {
        return Err(Error::DecodeMessage(einval()));
    }

    // We need to track if a SecCtx was received, because it's valid
    // for the guest to send an empty SecCtx (i.e, nr_secctx == 0)
    let mut secctx_received = false;

    let mut buf = &request_bytes[skip..];
    while !buf.is_empty() {
        let (extension_header, remaining_bytes) = take_object::<ExtHeader>(buf)?;

        let extension_size = (extension_header.size as usize)
            .checked_sub(size_of::<ExtHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        let (current_extension_bytes, next_extension_bytes) =
            remaining_bytes.split_at(extension_size);

        let ext_type = ExtType::try_from(extension_header.ext_type)
            .map_err(|_| Error::DecodeMessage(einval()))?;

        match ext_type {
            ExtType::SecCtx(nr_secctx) => {
                if !options.contains(FsOptions::SECURITY_CTX) || secctx_received {
                    return Err(Error::DecodeMessage(einval()));
                }

                secctx_received = true;
                extensions.secctx = parse_security_context(nr_secctx, current_extension_bytes)?;
                debug!("Extension received: {} SecCtx", nr_secctx);
            }
            ExtType::SupGroups => {
                if !options.contains(FsOptions::CREATE_SUPP_GROUP) || extensions.sup_gid.is_some() {
                    return Err(Error::DecodeMessage(einval()));
                }

                extensions.sup_gid = parse_sup_groups(current_extension_bytes)?.into();
                debug!("Extension received: SupGroups({:?})", extensions.sup_gid);
            }
        }

        // Let's process the next extension
        buf = next_extension_bytes;
    }

    // The SupGroup extension can be missing, since it is only sent if needed.
    // A SecCtx is always sent in create/synlink/mknod/mkdir if supported.
    if options.contains(FsOptions::SECURITY_CTX) && !secctx_received {
        return Err(Error::MissingExtension);
    }

    Ok(extensions)
}
