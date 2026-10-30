// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The POSIX shared-memory calls behind every object the workspace maps
//! (ADR-0013): creating an object exclusively, sized and on Linux reserved
//! ([`Mapping::create_exclusive`]); opening one in two steps, so a caller
//! can check its length and read its header through the descriptor before
//! it maps ([`Opened`], then [`Opened::map`]); and unlinking a name only
//! while it names the caller's object ([`Mapping::unlink_if_token`]).
//! Nothing here reads or writes a header; the caller decides what the
//! bytes mean.

use std::ffi::{CStr, CString};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Reservation attempts on Linux before [`Error::NoSpace`] with `EINTR`.
/// An interrupted reservation starts over, so the bound keeps a process
/// signalled faster than one completes from retrying for ever.
pub const RESERVE_ATTEMPTS: u32 = 8;

/// Re-tries [`wait_out_creator`] gives an unfinished creator, one
/// [`CREATE_RACE_PAUSE`] apart.
pub const CREATE_RACE_TRIES: u32 = 50;

/// The pause between two of the [`CREATE_RACE_TRIES`].
pub const CREATE_RACE_PAUSE: Duration = Duration::from_millis(1);

/// Interruptions a `pread` of a header rides out before it gives up.
#[cfg(target_os = "linux")]
const MAX_INTERRUPTIONS: u32 = 8;

/// The permissions a created object gets: its owner alone reads and writes.
const OBJECT_MODE: libc::c_uint = 0o600;

/// Why a shared-memory call failed. Exhaustive on purpose: each crate maps
/// every variant into its own error, and a new variant must break that
/// build (ADR-0013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `shm_open(3)` or the `fstat(2)` after it failed; the field is its
    /// `errno` (`EEXIST` from an exclusive creation whose name already
    /// holds an object, `ENOENT` from an open of a name that holds none,
    /// `EACCES` from a runtime that refuses POSIX shared memory, `EBADF`
    /// from a descriptor that is not open).
    Open(i32),
    /// `ftruncate(2)` could not size the new object; the field is its
    /// `errno` (`EFBIG`, `ENOSPC`).
    Truncate(i32),
    /// Linux could not reserve a new object's pages: `posix_fallocate(3)`
    /// failed, with `ENOSPC` on a full `/dev/shm`, `ENOMEM`, or `EINTR`
    /// after [`RESERVE_ATTEMPTS`] tries. Never returned off Linux.
    NoSpace {
        /// Bytes the object needed.
        need: u64,
        /// The error number `posix_fallocate` returned.
        errno: i32,
    },
    /// `mmap(2)` failed; the field is its `errno`.
    Map(i32),
    /// The name holds a NUL byte, which no C string can carry.
    InvalidName,
    /// The object is shorter than the caller needs: `have` bytes where
    /// `need` are needed. An object at size zero is one a creator has made
    /// and not yet sized.
    TooSmall {
        /// Bytes the object has.
        have: u64,
        /// Bytes the caller needs.
        need: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(e) => write!(f, "shm_open failed: errno {e}"),
            Self::Truncate(e) => write!(f, "ftruncate failed: errno {e}"),
            Self::NoSpace { need, errno } => write!(
                f,
                "could not reserve {need} bytes of shared memory: posix_fallocate failed with errno {errno}"
            ),
            Self::Map(e) => write!(f, "mmap failed: errno {e}"),
            Self::InvalidName => f.write_str("shared-memory name contains a NUL byte"),
            Self::TooSmall { have, need } => {
                write!(f, "shared-memory object is {have} bytes but {need} are needed")
            }
        }
    }
}

impl std::error::Error for Error {}

/// The `errno` of the last failing call on this thread. Read it straight
/// after the call that failed, before any other call to the C library.
#[must_use]
pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A shared-memory object's name, as the C library takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name(CString);

impl Name {
    /// The name as a C string.
    ///
    /// # Errors
    /// [`Error::InvalidName`] if `name` holds an interior NUL byte.
    pub fn new(name: &str) -> Result<Self, Error> {
        CString::new(name).map(Self).map_err(|_| Error::InvalidName)
    }

    /// The name for the C library.
    #[must_use]
    pub fn as_c(&self) -> &CStr {
        &self.0
    }

    /// The name as it was given, or the empty string if it is not UTF-8.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.to_str().unwrap_or("")
    }
}

/// Size in bytes of the object behind `fd`, from `fstat(2)`.
///
/// # Errors
/// The `errno` `fstat` set: `EBADF` for a descriptor that is not open.
pub fn object_len(fd: libc::c_int) -> Result<u64, i32> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat writes a `stat` into the buffer it is given and returns
    // non-zero on failure, in which case the buffer is never read; `fd` is
    // an integer the caller holds.
    let rc = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if rc != 0 {
        return Err(errno());
    }
    // SAFETY: fstat succeeded, so the buffer holds an initialised `stat`.
    let st = unsafe { st.assume_init() };
    Ok(u64::try_from(st.st_size).unwrap_or(0))
}

/// Allocate the pages of the first `len` bytes of the object behind `fd`
/// with `posix_fallocate(3)`, up to [`RESERVE_ATTEMPTS`] attempts.
///
/// Linux answers the first touch of a tmpfs page the tmpfs cannot supply
/// with SIGBUS; reserving makes a full `/dev/shm` an error here instead. A
/// reservation past the end does not grow a shared-memory object, so
/// callers reserve what they have sized.
///
/// # Errors
/// The error number `posix_fallocate` returned: `ENOSPC`, `ENOMEM`,
/// `EINTR` after every attempt, or another for a descriptor nothing can
/// reserve, such as one not open for writing.
#[cfg(target_os = "linux")]
pub fn reserve_pages(fd: libc::c_int, len: libc::off_t) -> Result<(), i32> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        // SAFETY: posix_fallocate reads only its integer arguments and
        // allocates storage for the object behind `fd`, which the caller
        // holds open; it touches no memory of this process, and it returns
        // an error number rather than setting errno.
        match unsafe { libc::posix_fallocate(fd, 0, len) } {
            0 => return Ok(()),
            libc::EINTR if attempts < RESERVE_ATTEMPTS => {}
            errno => return Err(errno),
        }
    }
}

/// Nothing to reserve off Linux: a first touch there does not fault for
/// want of room.
///
/// # Errors
/// None.
#[cfg(not(target_os = "linux"))]
pub fn reserve_pages(_fd: libc::c_int, _len: libc::off_t) -> Result<(), i32> {
    Ok(())
}

/// Size the object behind `fd` to `len` bytes, and on Linux reserve its
/// pages.
///
/// # Errors
/// [`Error::Truncate`] if `ftruncate(2)` refuses the size (with `EFBIG`
/// when `len` does not fit a file offset), and on Linux [`Error::NoSpace`]
/// if the pages cannot be reserved.
pub fn size_and_reserve(fd: libc::c_int, len: usize) -> Result<(), Error> {
    let off = libc::off_t::try_from(len).map_err(|_| Error::Truncate(libc::EFBIG))?;
    // SAFETY: ftruncate reads only its integer arguments and resizes the
    // object behind `fd`, which the caller holds open; it touches no memory
    // of this process.
    if unsafe { libc::ftruncate(fd, off) } != 0 {
        return Err(Error::Truncate(errno()));
    }
    reserve_pages(fd, off).map_err(|errno| Error::NoSpace {
        need: len as u64,
        errno,
    })
}

/// Read `buf.len()` bytes at `offset` of the object behind `fd` with
/// `pread(2)`, riding out a few interruptions. On a tmpfs a page never
/// allocated reads as zeros and stays unallocated, so a header can be read
/// from an object whose pages are not reserved, where a load through a
/// mapping would allocate the page, and a full tmpfs answer with SIGBUS.
///
/// # Errors
/// [`Error::TooSmall`] if the object ends before the bytes do, with the
/// length reached as `have`; [`Error::Open`] with the `errno` of a read
/// that failed.
#[cfg(target_os = "linux")]
pub fn pread_exact(fd: libc::c_int, offset: usize, buf: &mut [u8]) -> Result<(), Error> {
    let mut got = 0;
    let mut interruptions = 0;
    while got < buf.len() {
        let rest = &mut buf[got..];
        let Ok(at) = libc::off_t::try_from(offset + got) else {
            return Err(Error::Open(libc::EOVERFLOW));
        };
        // SAFETY: pread writes at most `rest.len()` bytes into `rest`, which
        // is valid for writes of that many, and only reads the object behind
        // `fd`, which the caller holds open.
        let n = unsafe { libc::pread(fd, rest.as_mut_ptr().cast(), rest.len(), at) };
        if n > 0 {
            got += n as usize;
            continue;
        }
        if n == 0 {
            return Err(Error::TooSmall {
                have: (offset + got) as u64,
                need: (offset + buf.len()) as u64,
            });
        }
        let e = errno();
        if e != libc::EINTR || interruptions == MAX_INTERRUPTIONS {
            return Err(Error::Open(e));
        }
        interruptions += 1;
    }
    Ok(())
}

/// Map the first `len` bytes of the object behind `fd`, at least that long,
/// read-only, hand the mapping's start to `read`, and unmap. For platforms
/// whose `pread` does not read a shared-memory object, such as macOS, which
/// backs one with ordinary virtual memory, not a tmpfs of fixed size, so a
/// first touch does not fail for want of room.
///
/// # Errors
/// [`Error::Map`] with the `errno` of a failed `mmap(2)`.
pub fn with_prefix_mapped<T>(
    fd: libc::c_int,
    len: usize,
    read: impl FnOnce(*const u8) -> T,
) -> Result<T, Error> {
    // SAFETY: maps `len` bytes of an object the caller has checked is at
    // least that long, read-only; the result is checked before use.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(Error::Map(errno()));
    }
    let value = read(ptr as *const u8);
    // SAFETY: unmaps exactly the mapping made above, which nothing refers
    // to any more: `read` has returned, and the pointer it was given is
    // not one it may keep.
    unsafe { libc::munmap(ptr, len) };
    Ok(value)
}

/// Remove `name`: `Ok(true)` when the name was removed, `Ok(false)` when
/// it held nothing. Mappings stay valid until they unmap.
///
/// # Errors
/// The `errno` of a failure other than `ENOENT`.
pub fn unlink(name: &Name) -> Result<bool, i32> {
    // SAFETY: `name` is a valid NUL-terminated string for the duration of
    // the call, and shm_unlink touches nothing else.
    if unsafe { libc::shm_unlink(name.as_c().as_ptr()) } == 0 {
        return Ok(true);
    }
    match errno() {
        libc::ENOENT => Ok(false),
        e => Err(e),
    }
}

/// Run `attempt`, and again after [`CREATE_RACE_PAUSE`] while `unfinished`
/// holds for its result (what a creator that has not finished leaves: an
/// object at size zero, an unpublished header), at most
/// [`CREATE_RACE_TRIES`] times more; returns the last result.
pub fn wait_out_creator<T>(mut attempt: impl FnMut() -> T, unfinished: impl Fn(&T) -> bool) -> T {
    let mut result = attempt();
    for _ in 0..CREATE_RACE_TRIES {
        if !unfinished(&result) {
            break;
        }
        std::thread::sleep(CREATE_RACE_PAUSE);
        result = attempt();
    }
    result
}

/// An object opened but not yet mapped, whose length and header a caller
/// checks through the descriptor before it touches a page. One from
/// [`Opened::open`] closes its descriptor when dropped; one from
/// [`Opened::from_fd`] never closes the caller's.
#[derive(Debug)]
pub struct Opened {
    /// `None` once the descriptor has gone to a mapping.
    fd: Option<libc::c_int>,
    /// `None` once the name has gone to a mapping.
    name: Option<Name>,
    have: u64,
    /// Whether dropping this handle closes the descriptor.
    closes: bool,
    /// Whether the mapping made from this handle closes it.
    mapping_owns_fd: bool,
}

impl Opened {
    /// Open the object `name` holds for reading and writing, without
    /// creating one. The handle owns the descriptor.
    ///
    /// # Errors
    /// [`Error::Open`] with the `errno` of `shm_open(3)` (`ENOENT` when the
    /// name holds nothing) or of the `fstat(2)` that sizes it; either way
    /// nothing is left open.
    pub fn open(name: Name) -> Result<Self, Error> {
        // SAFETY: `name` is a valid NUL-terminated string for the duration
        // of the call; shm_open only opens, never creates.
        let fd = unsafe { libc::shm_open(name.as_c().as_ptr(), libc::O_RDWR, 0) };
        if fd < 0 {
            return Err(Error::Open(errno()));
        }
        match object_len(fd) {
            Ok(have) => Ok(Self {
                fd: Some(fd),
                name: Some(name),
                have,
                closes: true,
                mapping_owns_fd: true,
            }),
            Err(e) => {
                // SAFETY: `fd` was opened above and nothing else holds it.
                unsafe { libc::close(fd) };
                Err(Error::Open(e))
            }
        }
    }

    /// Take up a descriptor the caller holds, under `name` for the record.
    /// The handle never closes it; the mapping made from it does only if
    /// `owns_fd`. Neither unlinks the name, which may be synthetic.
    ///
    /// # Errors
    /// [`Error::Open`] with the `errno` of the `fstat(2)` that sizes the
    /// object (`EBADF` when the descriptor is not open). The descriptor is
    /// left as it was.
    pub fn from_fd(name: Name, fd: libc::c_int, owns_fd: bool) -> Result<Self, Error> {
        let have = object_len(fd).map_err(Error::Open)?;
        Ok(Self {
            fd: Some(fd),
            name: Some(name),
            have,
            closes: false,
            mapping_owns_fd: owns_fd,
        })
    }

    /// The descriptor, for reading the header before mapping; never -1.
    #[must_use]
    pub fn fd(&self) -> libc::c_int {
        self.fd.unwrap_or(-1)
    }

    /// The object's length in bytes when it was opened.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.have
    }

    /// Whether the object had no bytes when it was opened, as a creator
    /// leaves it before sizing it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.have == 0
    }

    /// Whether the object holds at least `need` bytes.
    ///
    /// # Errors
    /// [`Error::TooSmall`] when it does not.
    pub fn at_least(&self, need: usize) -> Result<(), Error> {
        if self.have < need as u64 {
            return Err(Error::TooSmall {
                have: self.have,
                need: need as u64,
            });
        }
        Ok(())
    }

    /// Map the first `len` bytes for reading and writing.
    ///
    /// # Errors
    /// [`Error::TooSmall`] if the object is shorter than `len`, and
    /// [`Error::Map`] with the `errno` of a failed `mmap(2)`. Either way
    /// the handle is dropped, which closes a descriptor it opened and
    /// leaves one the caller holds.
    pub fn map(mut self, len: usize) -> Result<Mapping, Error> {
        self.at_least(len)?;
        let fd = self.fd();
        let ptr = map_rw(fd, len)?;
        // Moved to the mapping, so this handle's drop closes nothing.
        let name = self.name.take().unwrap_or_else(|| Name(CString::default()));
        self.fd = None;
        Ok(Mapping {
            ptr,
            len,
            fd,
            owns_fd: self.mapping_owns_fd,
            name,
        })
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        if let (Some(fd), true) = (self.fd.take(), self.closes) {
            // SAFETY: `fd` was opened by `Opened::open`, nothing else holds
            // it, and no mapping took it.
            unsafe { libc::close(fd) };
        }
    }
}

fn map_rw(fd: libc::c_int, len: usize) -> Result<*mut u8, Error> {
    // SAFETY: maps `len` bytes of an object the caller has sized or checked
    // to be at least that long; the result is checked before use.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(Error::Map(errno()));
    }
    Ok(ptr as *mut u8)
}

/// A shared mapping of a shared-memory object, unmapped when dropped, with
/// its descriptor closed if it owns it. Dropping it never unlinks the name;
/// an owner calls [`Mapping::unlink_if_token`] first.
pub struct Mapping {
    ptr: *mut u8,
    len: usize,
    fd: libc::c_int,
    owns_fd: bool,
    name: Name,
}

// SAFETY: a mapping is bytes another process may write concurrently, which
// every access through `ptr()` accounts for at the caller (the SeqLock and
// atomic protocols of the ring, the store and the region); the mapping
// itself is owned by one handle and can move between threads. It is not
// `Sync`: a user that shares it states its own protocol.
unsafe impl Send for Mapping {}

impl fmt::Debug for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mapping")
            .field("name", &self.name.as_str())
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl Mapping {
    /// Create the object `name`, which must be free, `len` bytes long, and
    /// map it for reading and writing: `shm_open(3)` with `O_EXCL` and mode
    /// `0o600`, [`size_and_reserve`], `mmap(2)`. A failure after the object
    /// exists unlinks it, leaving nothing for a later open to map. The bytes
    /// are the kernel's zero pages; the caller writes its header, its magic
    /// last.
    ///
    /// # Errors
    /// [`Error::Open`] with the `errno` of `shm_open` (`EEXIST` when the
    /// name already holds an object); [`Error::Truncate`] if the object
    /// cannot be sized; [`Error::NoSpace`] on Linux if its pages cannot be
    /// reserved; [`Error::Map`] if it cannot be mapped.
    pub fn create_exclusive(name: Name, len: usize) -> Result<Self, Error> {
        let flags = libc::O_CREAT | libc::O_EXCL | libc::O_RDWR;
        // SAFETY: `name` is a valid NUL-terminated string for the duration
        // of the call, and shm_open touches nothing else.
        let fd = unsafe { libc::shm_open(name.as_c().as_ptr(), flags, OBJECT_MODE) };
        if fd < 0 {
            return Err(Error::Open(errno()));
        }
        let abandon = |e: Error| -> Result<Self, Error> {
            // SAFETY: `name` names the object this call created and `fd` is
            // its descriptor, which nothing else holds.
            unsafe {
                libc::shm_unlink(name.as_c().as_ptr());
                libc::close(fd);
            }
            Err(e)
        };
        if let Err(e) = size_and_reserve(fd, len) {
            return abandon(e);
        }
        let ptr = match map_rw(fd, len) {
            Ok(ptr) => ptr,
            Err(e) => return abandon(e),
        };
        Ok(Self {
            ptr,
            len,
            fd,
            owns_fd: true,
            name,
        })
    }

    /// The start of the mapping, page aligned, valid for `len()` bytes as
    /// long as the mapping lives.
    #[inline]
    #[must_use]
    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// The mapping's length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the mapping has no bytes, which no constructor produces.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The descriptor the mapping was made from, or -1 once
    /// [`Mapping::close_fd`] has closed it.
    #[inline]
    #[must_use]
    pub fn fd(&self) -> libc::c_int {
        self.fd
    }

    /// The name the object was created or opened under.
    #[must_use]
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Stop owning the descriptor, so the drop leaves it open: for a
    /// constructor over a caller's descriptor that fails after mapping.
    pub fn leave_fd_open(&mut self) {
        self.owns_fd = false;
    }

    /// Close the descriptor now, if the mapping owns it, and forget it: the
    /// mapping keeps the object alive without it. `fd()` is then -1.
    pub fn close_fd(&mut self) {
        if self.owns_fd {
            // SAFETY: `fd` is the descriptor this mapping owns, which nothing
            // else holds; the mapping does not need it to stay valid.
            unsafe { libc::close(self.fd) };
        }
        self.fd = -1;
        self.owns_fd = false;
    }

    /// On Linux, ask for transparent huge pages behind the mapping; a
    /// refusal changes nothing.
    pub fn advise_hugepages(&self) {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: advises on exactly this mapping; madvise changes no
            // contents and a refusal is harmless.
            let _ = unsafe { libc::madvise(self.ptr.cast(), self.len, libc::MADV_HUGEPAGE) };
        }
    }

    /// Unlink the name only while it still names this object; `true` when
    /// it did.
    ///
    /// POSIX has no call that removes a name only while it names a given
    /// object, and an object has no identity comparable across two opens on
    /// every platform (macOS reports no inode). So the mapping stores a
    /// random non-zero token in the 8-byte word at `token_offset`, a header
    /// word the caller reserves for it that is zero in every object not
    /// being dropped, reads the word back through the name (with `pread` on
    /// Linux, which touches no page, elsewhere through a read-only mapping),
    /// and unlinks the name straight after, only if its own token came
    /// back. A successor that took the name keeps its object; a name that
    /// holds nothing, cannot be read, or holds another object is left.
    ///
    /// The race that remains is the time from the open of the name to the
    /// `shm_unlink`, a few calls: a successor that unlinks the name and
    /// creates its object within it still loses its name.
    ///
    /// # Panics
    /// If the word at `token_offset` is not an aligned 8-byte word inside
    /// the mapping, which is a caller's bug.
    pub fn unlink_if_token(&self, token_offset: usize) -> bool {
        use std::hash::BuildHasher;
        assert!(
            token_offset.is_multiple_of(8) && token_offset + 8 <= self.len,
            "the unlink token must be an aligned word inside the mapping"
        );
        // Keyed by the operating system's randomness; never zero.
        let token = std::collections::hash_map::RandomState::new()
            .hash_one((std::process::id(), self.ptr as usize))
            .max(1);
        // SAFETY: the word at `token_offset` lies inside the mapping,
        // aligned, and by the caller's contract nothing reads or writes it
        // as anything but this word; the mapping holds it until the unmap
        // that follows the drop.
        let word = unsafe { &*(self.ptr.add(token_offset) as *const AtomicU64) };
        word.store(token, Ordering::SeqCst);
        // SAFETY: `name` is a valid NUL-terminated string for the duration
        // of the call, and shm_open touches nothing else.
        let fd = unsafe { libc::shm_open(self.name.as_c().as_ptr(), libc::O_RDONLY, 0) };
        if fd < 0 {
            return false;
        }
        let this_object = read_word(fd, token_offset) == Some(token);
        if this_object {
            // SAFETY: `name` is a valid NUL-terminated string for the
            // duration of the call, and shm_unlink touches nothing else.
            unsafe { libc::shm_unlink(self.name.as_c().as_ptr()) };
        }
        // SAFETY: `fd` was opened above and nothing else holds it.
        unsafe { libc::close(fd) };
        this_object
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by mmap for `len` bytes and is unmapped
        // exactly once, here; `fd` is closed only when this mapping owns it.
        // After this drop nothing refers to the mapping.
        unsafe {
            libc::munmap(self.ptr.cast(), self.len);
            if self.owns_fd {
                libc::close(self.fd);
            }
        }
    }
}

/// The 8-byte word at `offset` of the object behind `fd`, or `None` when
/// the object cannot be read that far.
#[cfg(target_os = "linux")]
fn read_word(fd: libc::c_int, offset: usize) -> Option<u64> {
    let mut word = [0u8; 8];
    pread_exact(fd, offset, &mut word).ok()?;
    Some(u64::from_ne_bytes(word))
}

/// The 8-byte word at `offset` of the object behind `fd`, loaded through a
/// read-only mapping, or `None` when the object is too short or cannot be
/// mapped.
#[cfg(not(target_os = "linux"))]
fn read_word(fd: libc::c_int, offset: usize) -> Option<u64> {
    let len = offset + 8;
    if !matches!(object_len(fd), Ok(have) if have >= len as u64) {
        return None;
    }
    with_prefix_mapped(fd, len, |ptr| {
        // The token was stored through the object's own mapping before the
        // name was opened. This load through another mapping is relaxed,
        // the only atomic load std allows through a read-only mapping; the
        // sequentially consistent fence keeps that store ahead of it.
        std::sync::atomic::fence(Ordering::SeqCst);
        // SAFETY: `ptr` is the page-aligned start of a live mapping of `len`
        // bytes, so the word at `offset` lies inside it, aligned; it is only
        // ever accessed atomically.
        unsafe { &*(ptr.add(offset) as *const AtomicU64) }.load(Ordering::Relaxed)
    })
    .ok()
}

// ---- Copying shared bytes under a SeqLock --------------------------------

/// Copy `dst.len()` bytes of shared memory at `src` into `dst`, as relaxed
/// atomic loads of the eight-byte words that cover them.
///
/// This is how a SeqLock reader copies what a writer may be writing at the
/// same moment: every access to the shared bytes is atomic, so a racing
/// write can make the copy stale, which the reader's second counter load
/// catches, but never makes it undefined behaviour, which a plain memory
/// copy racing a write is in Rust whether or not the copy is kept. On
/// x86-64 and AArch64 a relaxed load is an ordinary load. The words are
/// copied in memory order, so the bytes land as a plain copy would put them.
///
/// # Safety
///
/// `src` is 8-byte aligned and valid for reads of `dst.len()` bytes rounded
/// up to a multiple of eight while the call runs, and every concurrent
/// access to those bytes is atomic.
#[inline]
pub unsafe fn load_words(src: *const u8, dst: &mut [u8]) {
    for (i, chunk) in dst.chunks_mut(8).enumerate() {
        // SAFETY: the caller keeps `src + 8 i` 8-byte aligned and valid for
        // the call, and the word is only ever accessed atomically.
        let word = unsafe { AtomicU64::from_ptr(src.add(i * 8).cast::<u64>().cast_mut()) }
            .load(Ordering::Relaxed);
        chunk.copy_from_slice(&word.to_ne_bytes()[..chunk.len()]);
    }
}

/// Copy `src` into shared memory at `dst`, as relaxed atomic stores of
/// eight-byte words: the writer's half of [`load_words`].
///
/// # Safety
///
/// `dst` is 8-byte aligned and valid for writes of `src.len()` bytes while
/// the call runs, every concurrent access to those bytes is atomic, and
/// `src.len()` is a multiple of eight.
#[inline]
pub unsafe fn store_words(dst: *mut u8, src: &[u8]) {
    debug_assert!(
        src.len().is_multiple_of(8),
        "store_words copies whole words"
    );
    for (i, chunk) in src.chunks_exact(8).enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        // SAFETY: the caller keeps `dst + 8 i` 8-byte aligned and valid for
        // the call, and the word is only ever accessed atomically.
        unsafe { AtomicU64::from_ptr(dst.add(i * 8).cast::<u64>()) }
            .store(u64::from_ne_bytes(word), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{load_words, store_words, unlink, Error, Mapping, Name, Opened};
    use std::sync::{Mutex, MutexGuard, PoisonError};

    /// The word copies move bytes exactly as a plain copy would: whole
    /// words, and a partial last word read into a shorter buffer.
    #[test]
    fn words_copy_bytes_in_memory_order() {
        let mut shared = [0u64; 4];
        let src: Vec<u8> = (1..=24).collect();
        // SAFETY: `shared` is 8-byte aligned and 32 bytes long, and nothing
        // else touches it.
        unsafe { store_words(shared.as_mut_ptr().cast::<u8>(), &src) };
        let mut whole = [0u8; 24];
        // SAFETY: as above; 24 bytes are three whole words inside it.
        unsafe { load_words(shared.as_ptr().cast::<u8>(), &mut whole) };
        assert_eq!(whole.as_slice(), src.as_slice());
        let mut part = [0u8; 13];
        // SAFETY: as above; 13 bytes round up to two words inside it.
        unsafe { load_words(shared.as_ptr().cast::<u8>(), &mut part) };
        assert_eq!(part.as_slice(), &src[..13]);
        assert_eq!(shared[3], 0, "no word past the source was written");
    }

    /// Descriptor numbers are reused as soon as they are closed, and one
    /// test here checks that a descriptor was closed, so the tests run one
    /// at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A name private to this process and test, at most 30 bytes, with
    /// nothing left under it by an earlier run.
    fn name(tag: &str) -> Name {
        let name = format!("/shm-{tag}-{:x}", std::process::id());
        assert!(name.len() <= 30, "{name} is longer than macOS allows");
        let name = Name::new(&name).unwrap();
        unlink(&name).unwrap();
        name
    }

    fn fd_is_open(fd: libc::c_int) -> bool {
        // SAFETY: fcntl with F_GETFD reads a flag and touches no memory.
        unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
    }

    #[test]
    fn a_name_with_a_nul_byte_is_refused() {
        assert_eq!(Name::new("a\0b").unwrap_err(), Error::InvalidName);
        assert_eq!(Name::new("/plain").unwrap().as_str(), "/plain");
    }

    #[test]
    fn an_exclusive_creation_refuses_a_taken_name_and_never_unlinks_on_drop() {
        let _serial = serial();
        let name = name("excl");
        let first = Mapping::create_exclusive(name.clone(), 4096).unwrap();
        assert_eq!(
            Mapping::create_exclusive(name.clone(), 4096).unwrap_err(),
            Error::Open(libc::EEXIST)
        );
        drop(first);
        assert!(Opened::open(name.clone()).is_ok(), "a drop unlinks nothing");
        assert!(unlink(&name).unwrap());
        assert!(!unlink(&name).unwrap());
        assert_eq!(Opened::open(name).unwrap_err(), Error::Open(libc::ENOENT));
    }

    #[test]
    fn an_open_maps_what_the_creator_wrote() {
        let _serial = serial();
        let name = name("rw");
        let creator = Mapping::create_exclusive(name.clone(), 8192).unwrap();
        // SAFETY: byte 4100 lies inside the 8192-byte mapping, which nothing
        // else reads until the mapping below is made.
        unsafe { creator.ptr().add(4100).write(0x5a) };
        let opened = Opened::open(name.clone()).unwrap();
        assert!(
            opened.len() >= 8192,
            "the object is at least as long as it was sized"
        );
        assert!(!opened.is_empty());
        opened.at_least(8192).unwrap();
        assert_eq!(
            opened.at_least(1 << 30).unwrap_err(),
            Error::TooSmall {
                have: opened.len(),
                need: 1 << 30
            }
        );
        let reader = opened.map(8192).unwrap();
        assert_eq!(reader.len(), 8192);
        assert_eq!(reader.name(), &name);
        // SAFETY: byte 4100 lies inside the 8192-byte mapping, written once
        // above before this mapping was made.
        assert_eq!(unsafe { reader.ptr().add(4100).read() }, 0x5a);
        drop(reader);
        assert!(creator.unlink_if_token(0));
    }

    #[test]
    fn the_unlink_token_leaves_a_successors_object_under_the_name() {
        let _serial = serial();
        let name = name("token");
        let earlier = Mapping::create_exclusive(name.clone(), 4096).unwrap();
        assert!(unlink(&name).unwrap());
        let later = Mapping::create_exclusive(name.clone(), 4096).unwrap();
        assert!(!earlier.unlink_if_token(64), "the name is the successor's");
        assert!(Opened::open(name.clone()).is_ok());
        assert!(
            later.unlink_if_token(64),
            "the successor removes its own name"
        );
        assert_eq!(
            Opened::open(name.clone()).unwrap_err(),
            Error::Open(libc::ENOENT)
        );
        assert!(
            !earlier.unlink_if_token(64),
            "a name that holds nothing is left"
        );
    }

    #[test]
    fn a_borrowed_descriptor_stays_the_callers_unless_the_mapping_owns_it() {
        let _serial = serial();
        let name = name("fd");
        let creator = Mapping::create_exclusive(name.clone(), 4096).unwrap();
        // SAFETY: dup of a descriptor this test's mapping owns; checked.
        let borrowed = unsafe { libc::dup(creator.fd()) };
        assert!(borrowed >= 0);
        let view = Opened::from_fd(name.clone(), borrowed, false)
            .unwrap()
            .map(4096)
            .unwrap();
        drop(view);
        assert!(
            fd_is_open(borrowed),
            "owns_fd=false leaves the descriptor open"
        );
        let opened = Opened::from_fd(name.clone(), borrowed, true).unwrap();
        assert_eq!(opened.fd(), borrowed);
        drop(opened);
        assert!(
            fd_is_open(borrowed),
            "an unmapped handle never closes a caller's descriptor"
        );
        let mut owned = Opened::from_fd(name.clone(), borrowed, true)
            .unwrap()
            .map(4096)
            .unwrap();
        owned.leave_fd_open();
        drop(owned);
        assert!(
            fd_is_open(borrowed),
            "leave_fd_open hands the descriptor back"
        );
        let mut owned = Opened::from_fd(name.clone(), borrowed, true)
            .unwrap()
            .map(4096)
            .unwrap();
        owned.close_fd();
        assert_eq!(owned.fd(), -1);
        assert!(
            !fd_is_open(borrowed),
            "close_fd closes a descriptor the mapping owns"
        );
        drop(owned);
        assert_eq!(
            Opened::from_fd(name.clone(), borrowed, false).unwrap_err(),
            Error::Open(libc::EBADF)
        );
        assert!(creator.unlink_if_token(0));
    }

    #[test]
    fn a_creator_that_cannot_size_its_object_leaves_the_name_free() {
        let _serial = serial();
        let name = name("huge");
        // A length no file offset holds is refused before the object is
        // sized, and the object it briefly created is gone.
        let err = Mapping::create_exclusive(name.clone(), usize::MAX).unwrap_err();
        assert!(matches!(err, Error::Truncate(_)), "got {err:?}");
        assert_eq!(Opened::open(name).unwrap_err(), Error::Open(libc::ENOENT));
    }
}
