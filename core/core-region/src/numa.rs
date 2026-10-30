// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `core_region::numa`: shared-memory backings for rings, on hugepages and
//! chosen NUMA nodes (module M01, which the HFT ring re-exports as
//! `hft_stages::numa`).
//!
//! - [`allocate_shm_backing`] makes a file-backed [`ShmBacking`], and
//!   [`allocate_hugepage_memfd`] an anonymous hugepage memfd (Linux), for
//!   `core_ring::PulseRing::from_fd`.
//! - [`numa_bind_memory`], [`pin_thread_to_numa_node`] and
//!   [`detect_numa_node_for_shm`] place memory and threads on nodes, and
//!   find where memory is.
//!
//! Placement is Linux-only: elsewhere it returns
//! [`NumaError::LibnumaMissing`]. The mapping calls go through
//! [`crate::shm`] (ADR-0013).

use std::path::Path;
use thiserror::Error;

#[cfg(target_os = "linux")]
use crate::shm;

/// Errors of this module's functions.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum NumaError {
    /// Making a memfd ([`allocate_hugepage_memfd`]) or duplicating a
    /// descriptor ([`dup_fd`]) failed; the string says what and why.
    #[error("hugepage allocation failed: {0}")]
    HugePageAlloc(String),
    /// Pinning a thread or binding memory to a NUMA node failed:
    /// `sched_setaffinity(2)` or `mbind(2)` refused, the node is past the
    /// 64 a binding can name, or a CPU number is past the `CPU_SETSIZE`
    /// (1024) a `cpu_set_t` can name.
    #[error("numa pin failed: cpu {cpu}, node {node}: {reason}")]
    NumaPin {
        /// The CPU the failure concerns, or -1 when it concerns no single
        /// CPU or the CPU number does not fit an `i32`.
        cpu: i32,
        /// The NUMA node being pinned or bound to.
        node: u32,
        /// What failed, with the error the kernel returned, if any.
        reason: String,
    },
    /// Caller requested a page size the kernel doesn't expose.
    /// Check `/sys/kernel/mm/hugepages` to see what's available.
    #[error("page size {size} not supported on this kernel; check /sys/kernel/mm/hugepages")]
    UnsupportedPageSize {
        /// Page-size designator that was unsupported (e.g. `"1G"`).
        size: &'static str,
    },
    /// The operation is Linux-only: binding memory, detecting a node,
    /// pinning a thread and hugepage memfds return this elsewhere. Nothing
    /// links libnuma; on Linux these are the kernel's system calls.
    #[error("NUMA placement, pinning and hugepage memfds are available only on Linux")]
    LibnumaMissing,
    /// Underlying I/O failure (typically while creating or sizing the SHM file).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Backing page size for a ring: larger pages mean fewer TLB misses on a
/// large ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    /// 4 KB — kernel default. Fine for rings ≤ 256 KB.
    Regular,
    /// 2 MB — for rings of 4 to 64 MB; needs the kernel's 2 MB hugepage pool.
    Huge2M,
    /// 1 GB — for rings ≥ 256 MB. Requires kernel boot parameter `hugepagesz=1G hugepages=N`.
    Huge1G,
}

impl PageSize {
    /// Page size in bytes.
    pub fn bytes(self) -> usize {
        match self {
            PageSize::Regular => 4 * 1024,
            PageSize::Huge2M => 2 * 1024 * 1024,
            PageSize::Huge1G => 1024 * 1024 * 1024,
        }
    }

    /// The `MAP_HUGE_*` bits (`<linux/mman.h>`) to pass with `MAP_HUGETLB`; 0
    /// for `Regular`.
    pub fn map_huge_flag(self) -> i32 {
        match self {
            PageSize::Regular => 0,
            // MAP_HUGE_2MB = 21 << MAP_HUGE_SHIFT (=26)
            PageSize::Huge2M => 21 << 26,
            // MAP_HUGE_1GB = 30 << MAP_HUGE_SHIFT (=26)
            PageSize::Huge1G => 30 << 26,
        }
    }
}

/// What [`allocate_shm_backing`] makes: a backing file's path, size, page
/// size and NUMA node.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ShmNumaConfig<'a> {
    /// Filesystem path for the SHM backing file (typically `/dev/shm/...`),
    /// which [`allocate_shm_backing`] creates and which must not exist yet.
    pub shm_path: &'a Path,
    /// Size in bytes, rounded up to whole pages.
    pub capacity_bytes: usize,
    /// Backing page size.
    pub page_size: PageSize,
    /// The node to bind the pages to (Linux only), or `None` for the
    /// kernel's default placement.
    pub numa_node: Option<u32>,
}

impl<'a> ShmNumaConfig<'a> {
    /// A backing of `capacity_bytes` at `shm_path`, on regular pages, with
    /// no NUMA preference.
    #[must_use]
    pub fn new(shm_path: &'a Path, capacity_bytes: usize) -> Self {
        Self {
            shm_path,
            capacity_bytes,
            page_size: PageSize::Regular,
            numa_node: None,
        }
    }

    /// This configuration at another path.
    #[must_use]
    pub fn with_shm_path(mut self, shm_path: &'a Path) -> Self {
        self.shm_path = shm_path;
        self
    }

    /// This configuration with another capacity in bytes.
    #[must_use]
    pub fn with_capacity_bytes(mut self, capacity_bytes: usize) -> Self {
        self.capacity_bytes = capacity_bytes;
        self
    }

    /// This configuration on the given page size.
    #[must_use]
    pub fn with_page_size(mut self, page_size: PageSize) -> Self {
        self.page_size = page_size;
        self
    }

    /// This configuration bound to `numa_node`, or to no node for `None`.
    #[must_use]
    pub fn with_numa_node(mut self, numa_node: Option<u32>) -> Self {
        self.numa_node = numa_node;
        self
    }
}

/// A backing file made by [`allocate_shm_backing`]. Dropping it removes the
/// path, if the path still names this file.
///
/// A mapping made from the file, such as a `core_ring::PulseRing::from_fd`
/// ring, stays valid after the drop; only opening the path fails. Keep the
/// backing while other processes may still attach by path.
#[derive(Debug)]
pub struct ShmBacking {
    file: std::fs::File,
    path: std::path::PathBuf,
}

impl ShmBacking {
    /// The backing file, whose descriptor `core_ring::PulseRing::from_fd`
    /// takes. It closes when the backing drops; a ring that should own a
    /// descriptor takes a [`dup_fd`] of it.
    pub fn file(&self) -> &std::fs::File {
        &self.file
    }

    /// The path the file was created at, which the drop removes.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::os::unix::io::AsRawFd for ShmBacking {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.file.as_raw_fd()
    }
}

impl std::os::unix::io::AsFd for ShmBacking {
    fn as_fd(&self) -> std::os::unix::io::BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl Drop for ShmBacking {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let ours = self.file.metadata();
        let there = std::fs::symlink_metadata(&self.path);
        match (ours, there) {
            (Ok(ours), Ok(there)) if ours.dev() == there.dev() && ours.ino() == there.ino() => {
                if let Err(e) = std::fs::remove_file(&self.path) {
                    tracing::warn!(path = %self.path.display(), error = %e, "could not remove the shm backing");
                }
            }
            _ => tracing::debug!(
                path = %self.path.display(),
                "the shm backing's path no longer names its file; left as it is"
            ),
        }
    }
}

/// Create a backing file at `cfg.shm_path` of `capacity_bytes` rounded up to
/// whole pages, bound to `cfg.numa_node` if set and, on Linux, with its
/// pages reserved by `posix_fallocate(3)`, after the binding so they are
/// allocated on that node: a full tmpfs is an error here, not SIGBUS at a
/// first touch.
///
/// Hand the backing's descriptor to `core_ring::PulseRing::from_fd`; the
/// file is removed when the [`ShmBacking`] drops. The file must not exist:
/// an existing one, perhaps a backing another process has mapped, is
/// refused and left alone, since truncating a live backing would SIGBUS its
/// readers. A process attaching to another's backing opens the path itself
/// and passes the descriptor to `PulseRing::from_fd`, which checks the ring
/// header rather than formatting it.
///
/// # Errors
///
/// A failed call leaves nothing at `cfg.shm_path` but the existing file of
/// the first error.
///
/// - [`NumaError::Io`] of kind `AlreadyExists` if a file exists at
///   `cfg.shm_path`.
/// - [`NumaError::Io`] of kind `InvalidInput` if `capacity_bytes` rounded up
///   to whole pages does not fit a `usize`.
/// - [`NumaError::UnsupportedPageSize`] if `cfg.page_size` is a hugepage size
///   whose kernel pool is not configured.
/// - [`NumaError::Io`] from creating or sizing the file.
/// - [`NumaError::LibnumaMissing`] if `cfg.numa_node` is set off Linux, or
///   [`NumaError::NumaPin`] if the kernel refuses the binding.
/// - On Linux, [`NumaError::Io`] with the error `posix_fallocate` returned
///   (`ENOSPC` for a full filesystem, `ENOMEM` at a memory limit, `EINTR`
///   after [`crate::shm::RESERVE_ATTEMPTS`] interrupted attempts).
pub fn allocate_shm_backing(cfg: &ShmNumaConfig<'_>) -> Result<ShmBacking, NumaError> {
    use std::os::unix::fs::OpenOptionsExt;

    let aligned = page_aligned(cfg.capacity_bytes, cfg.page_size).ok_or_else(|| {
        NumaError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "capacity_bytes {} rounded up to {}-byte pages does not fit a usize",
                cfg.capacity_bytes,
                cfg.page_size.bytes()
            ),
        ))
    })?;
    if matches!(cfg.page_size, PageSize::Huge2M | PageSize::Huge1G) {
        verify_hugepage_available(cfg.page_size)?;
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(cfg.shm_path)?;
    if let Err(e) = size_bind_and_reserve(&file, aligned, cfg.numa_node) {
        drop(file);
        let _ = std::fs::remove_file(cfg.shm_path);
        return Err(e);
    }

    tracing::info!(
        path = %cfg.shm_path.display(),
        bytes = aligned,
        page_size = ?cfg.page_size,
        numa_node = ?cfg.numa_node,
        "allocated shm backing"
    );

    Ok(ShmBacking {
        file,
        path: cfg.shm_path.to_path_buf(),
    })
}

/// `bytes` rounded up to a whole number of `page_size` pages, or `None` when
/// that does not fit a `usize`.
fn page_aligned(bytes: usize, page_size: PageSize) -> Option<usize> {
    let page = page_size.bytes();
    bytes.div_ceil(page).checked_mul(page)
}

/// Size a new backing file to `bytes`, bind it to `numa_node` if given, and
/// on Linux reserve its pages, after the binding so they are allocated
/// under it.
fn size_bind_and_reserve(
    file: &std::fs::File,
    bytes: usize,
    numa_node: Option<u32>,
) -> Result<(), NumaError> {
    file.set_len(bytes as u64)?;
    if let Some(node) = numa_node {
        bind_file_to_numa_node(file, bytes, node)?;
    }
    #[cfg(target_os = "linux")]
    reserve_file_pages(file, bytes)?;
    Ok(())
}

/// Create an anonymous memfd of `capacity_bytes` rounded up to whole pages,
/// on hugepages from the kernel's reserved pool unless `page_size` is
/// `Regular`, and return its descriptor, the caller's to close, for
/// `core_ring::PulseRing::from_fd`.
///
/// Its hugepages are guaranteed, where `madvise(MADV_HUGEPAGE)` on a tmpfs
/// file is only a request. It has no name to open, so another process gets
/// it by inheritance or descriptor passing (`SCM_RIGHTS`, `pidfd_getfd`).
///
/// # Errors
///
/// [`NumaError::HugePageAlloc`], with nothing left open, when the rounded
/// capacity does not fit a file offset, `name` contains a NUL byte,
/// `memfd_create` fails (most often an empty hugepage pool) or `ftruncate`
/// fails.
#[cfg(target_os = "linux")]
pub fn allocate_hugepage_memfd(
    name: &str,
    capacity_bytes: usize,
    page_size: PageSize,
) -> Result<libc::c_int, NumaError> {
    let aligned = page_aligned(capacity_bytes, page_size)
        .and_then(|bytes| libc::off_t::try_from(bytes).ok())
        .ok_or_else(|| {
            NumaError::HugePageAlloc(format!(
                "capacity_bytes {capacity_bytes} rounded up to {}-byte pages does not fit a file offset",
                page_size.bytes()
            ))
        })?;

    let cname = std::ffi::CString::new(name)
        .map_err(|_| NumaError::HugePageAlloc(format!("name {:?} contains nul byte", name)))?;

    const MFD_CLOEXEC: libc::c_uint = 0x0001;
    const MFD_HUGETLB: libc::c_uint = 0x0004;
    const MFD_HUGE_2MB: libc::c_uint = 21 << 26;
    const MFD_HUGE_1GB: libc::c_uint = 30 << 26;

    let mut flags = MFD_CLOEXEC;
    match page_size {
        PageSize::Huge2M => flags |= MFD_HUGETLB | MFD_HUGE_2MB,
        PageSize::Huge1G => flags |= MFD_HUGETLB | MFD_HUGE_1GB,
        PageSize::Regular => {}
    }

    // SAFETY: `cname` is a NUL-terminated CString that outlives the call and
    // `flags` is a valid MFD_* bitset; the kernel validates both.
    let fd = unsafe { libc::memfd_create(cname.as_ptr(), flags) };
    if fd < 0 {
        let errno = std::io::Error::last_os_error();
        return Err(NumaError::HugePageAlloc(format!(
            "memfd_create failed: {} (page_size={:?}, hugepage pool may be empty)",
            errno, page_size
        )));
    }

    // SAFETY: `fd` is the open descriptor returned just above; ftruncate
    // takes it by value, reads only its integer arguments and touches no
    // memory of this process.
    if unsafe { libc::ftruncate(fd, aligned) } != 0 {
        let errno = std::io::Error::last_os_error();
        // SAFETY: closes the descriptor memfd_create returned above, which
        // nothing else holds and which is not used again.
        unsafe { libc::close(fd) };
        return Err(NumaError::HugePageAlloc(format!(
            "ftruncate({}) failed: {}",
            aligned, errno
        )));
    }

    tracing::info!(
        name,
        bytes = aligned,
        page_size = ?page_size,
        "allocated hugepage memfd"
    );

    Ok(fd)
}

/// Off Linux: memfds are Linux-only.
///
/// # Errors
///
/// Always [`NumaError::LibnumaMissing`]; [`allocate_shm_backing`] is the
/// portable path.
#[cfg(not(target_os = "linux"))]
pub fn allocate_hugepage_memfd(
    _name: &str,
    _capacity_bytes: usize,
    _page_size: PageSize,
) -> Result<libc::c_int, NumaError> {
    Err(NumaError::LibnumaMissing)
}

fn verify_hugepage_available(size: PageSize) -> Result<(), NumaError> {
    let dir = match size {
        PageSize::Huge2M => "/sys/kernel/mm/hugepages/hugepages-2048kB",
        PageSize::Huge1G => "/sys/kernel/mm/hugepages/hugepages-1048576kB",
        PageSize::Regular => return Ok(()),
    };
    let nr_path = format!("{}/nr_hugepages", dir);
    let nr = std::fs::read_to_string(&nr_path).map_err(|_| NumaError::UnsupportedPageSize {
        size: match size {
            PageSize::Huge2M => "2MB",
            PageSize::Huge1G => "1GB",
            PageSize::Regular => unreachable!(),
        },
    })?;
    let nr: u64 = nr.trim().parse().unwrap_or(0);
    if nr == 0 {
        tracing::warn!(
            "hugepage pool for {:?} is 0 — set via `echo N > {}` or kernel cmdline",
            size,
            nr_path
        );
    }
    Ok(())
}

/// Bind a file's pages to `node` through a shared mapping made for the call.
/// On tmpfs the policy is kept on the inode, so the pages
/// [`reserve_file_pages`] allocates later land on `node`. No page is touched
/// here: on a tmpfs without room that would SIGBUS, where the reservation
/// returns an error.
#[cfg(target_os = "linux")]
fn bind_file_to_numa_node(file: &std::fs::File, bytes: usize, node: u32) -> Result<(), NumaError> {
    use std::os::unix::io::AsRawFd;
    if bytes == 0 {
        return Ok(());
    }
    // `false`: the descriptor stays the file's.
    let mapping = shm::Name::new("")
        .and_then(|name| shm::Opened::from_fd(name, file.as_raw_fd(), false))
        .and_then(|opened| opened.map(bytes))
        .map_err(shm_io)?;
    numa_bind_memory(mapping.ptr(), bytes, node)?;
    drop(mapping);
    tracing::debug!(node, bytes, "bound file pages to NUMA node");
    Ok(())
}

/// Reserve the first `bytes` of `file` with
/// [`crate::shm::reserve_pages`], so tmpfs allocates the pages now,
/// under the file's NUMA policy, rather than at a first touch that could
/// SIGBUS.
#[cfg(target_os = "linux")]
fn reserve_file_pages(file: &std::fs::File, bytes: usize) -> Result<(), NumaError> {
    use std::os::unix::io::AsRawFd;
    if bytes == 0 {
        return Ok(());
    }
    // `set_len` already accepted this size, so it fits an off_t.
    let len = libc::off_t::try_from(bytes)
        .map_err(|_| NumaError::Io(std::io::Error::from_raw_os_error(libc::EFBIG)))?;
    shm::reserve_pages(file.as_raw_fd(), len)
        .map_err(|errno| NumaError::Io(std::io::Error::from_raw_os_error(errno)))
}

/// The NUMA module's error for a shared-memory mechanism error: the errno
/// of the call that failed, or `InvalidInput` for a length the file does
/// not hold or a name it cannot take.
#[cfg(target_os = "linux")]
fn shm_io(e: shm::Error) -> NumaError {
    let io = match e {
        shm::Error::Open(errno)
        | shm::Error::Truncate(errno)
        | shm::Error::Map(errno)
        | shm::Error::NoSpace { errno, .. } => std::io::Error::from_raw_os_error(errno),
        shm::Error::InvalidName | shm::Error::TooSmall { .. } => {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
        }
    };
    NumaError::Io(io)
}

#[cfg(target_os = "linux")]
fn page_size() -> usize {
    // SAFETY: sysconf reads a constant; a failure returns -1, mapped to 4 KB.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(v).unwrap_or(4096).max(1)
}

/// The NUMA node holding the page at `addr`, via `get_mempolicy(2)` with
/// `MPOL_F_NODE | MPOL_F_ADDR` (which faults the page in as a read if it
/// does not exist yet).
#[cfg(target_os = "linux")]
fn mempolicy_node_of(addr: *const u8) -> Result<u32, NumaError> {
    // From <linux/mempolicy.h>; not exposed by libc 0.2.186.
    const MPOL_F_NODE: libc::c_ulong = 1 << 0;
    const MPOL_F_ADDR: libc::c_ulong = 1 << 1;
    let mut node: libc::c_int = -1;
    // SAFETY: get_mempolicy writes one c_int into `node`, takes no nodemask
    // (null, maxnode 0), and only inspects the page at `addr`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_get_mempolicy,
            &mut node as *mut libc::c_int,
            std::ptr::null_mut::<libc::c_ulong>(),
            0 as libc::c_ulong,
            addr,
            MPOL_F_NODE | MPOL_F_ADDR,
        )
    };
    if rc != 0 {
        return Err(NumaError::Io(std::io::Error::last_os_error()));
    }
    u32::try_from(node).map_err(|_| {
        NumaError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("get_mempolicy returned node {node}"),
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn bind_file_to_numa_node(
    _file: &std::fs::File,
    _bytes: usize,
    _node: u32,
) -> Result<(), NumaError> {
    Err(NumaError::LibnumaMissing)
}

/// Pin the calling thread to the CPUs of NUMA node `node`, or to
/// `cpu_subset`, which should be CPUs of `node`, so it runs beside its
/// ring's memory.
///
/// # Errors
///
/// - [`NumaError::NumaPin`] if a CPU number is `CPU_SETSIZE` (1024) or
///   more, before the affinity is touched, or if `sched_setaffinity(2)`
///   refuses the set (CPUs outside the process's allowed set, `EPERM`).
/// - [`NumaError::Io`] if `cpu_subset` is `None` and the node's CPU list
///   under `/sys/devices/system/node/` cannot be read.
/// - [`NumaError::LibnumaMissing`] off Linux.
pub fn pin_thread_to_numa_node(node: u32, cpu_subset: Option<&[u32]>) -> Result<(), NumaError> {
    #[cfg(target_os = "linux")]
    {
        let cpus = match cpu_subset {
            Some(list) => list.to_vec(),
            None => list_cpus_on_node(node)?,
        };
        // SAFETY: `cpu_set_t` is a plain bitmask for which all-zero is a
        // valid value, the empty set.
        let mut cpu_set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
        // SAFETY: CPU_ZERO clears the words of the local set it is given
        // and touches nothing else.
        unsafe { libc::CPU_ZERO(&mut cpu_set) };
        for &cpu in &cpus {
            let bit = cpu_set_bit(cpu).ok_or_else(|| NumaError::NumaPin {
                cpu: i32::try_from(cpu).unwrap_or(-1),
                node,
                reason: format!("CPU {cpu} is past the {CPU_SET_BITS} CPUs a cpu_set_t can name"),
            })?;
            // SAFETY: `bit` is below CPU_SET_BITS, which the const assertion
            // on it keeps within the local set, so CPU_SET sets that one bit
            // and touches nothing else. The check above matters: libc's
            // CPU_SET is an `extern "C"` fn that bounds-checks its index, and
            // a panic cannot unwind out of it, so a bad index would abort.
            unsafe { libc::CPU_SET(bit, &mut cpu_set) };
        }
        // SAFETY: sched_setaffinity(0, ...) applies to the calling thread
        // and reads exactly `size_of::<cpu_set_t>()` bytes of the local set,
        // the size passed; it writes nothing of this process's memory.
        let rc = unsafe {
            libc::sched_setaffinity(
                0,
                std::mem::size_of::<libc::cpu_set_t>(),
                &cpu_set as *const _,
            )
        };
        if rc != 0 {
            return Err(NumaError::NumaPin {
                cpu: -1,
                node,
                reason: std::io::Error::last_os_error().to_string(),
            });
        }
        tracing::debug!(node, cpus = ?cpus, "pinned thread to NUMA node");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (node, cpu_subset);
        Err(NumaError::LibnumaMissing)
    }
}

/// CPUs a `cpu_set_t` can name: `CPU_SETSIZE`, 1024 with glibc and musl.
#[cfg(target_os = "linux")]
const CPU_SET_BITS: usize = libc::CPU_SETSIZE as usize;

// A `cpu_set_t` holds that many bits, so CPU_SET never indexes past it for
// a bit below CPU_SET_BITS.
#[cfg(target_os = "linux")]
const _: () = assert!(CPU_SET_BITS <= 8 * std::mem::size_of::<libc::cpu_set_t>());

/// The bit for `cpu` in a `cpu_set_t`, or `None` for a CPU number the set
/// cannot name.
#[cfg(target_os = "linux")]
fn cpu_set_bit(cpu: u32) -> Option<usize> {
    usize::try_from(cpu).ok().filter(|&bit| bit < CPU_SET_BITS)
}

#[cfg(target_os = "linux")]
fn list_cpus_on_node(node: u32) -> Result<Vec<u32>, NumaError> {
    let path = format!("/sys/devices/system/node/node{}/cpulist", node);
    let s = std::fs::read_to_string(&path)?;
    let mut out = Vec::new();
    for tok in s.trim().split(',') {
        if let Some((lo, hi)) = tok.split_once('-') {
            let lo: u32 = lo.parse().unwrap_or(0);
            let hi: u32 = hi.parse().unwrap_or(0);
            out.extend(lo..=hi);
        } else if let Ok(v) = tok.parse::<u32>() {
            out.push(v);
        }
    }
    Ok(out)
}

/// The NUMA node holding the first page of the file at `shm_path`, faulting
/// the page in if it has none yet.
///
/// # Errors
///
/// Returns [`NumaError::Io`] when the file cannot be opened, is empty, cannot be
/// mapped, or `get_mempolicy(2)` fails; [`NumaError::LibnumaMissing`] off Linux.
#[cfg(target_os = "linux")]
pub fn detect_numa_node_for_shm(shm_path: &Path) -> Result<u32, NumaError> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::File::open(shm_path)?;
    let len = usize::try_from(file.metadata()?.len()).unwrap_or(0);
    if len == 0 {
        return Err(NumaError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "shm file is empty",
        )));
    }
    let bytes = len.min(page_size());
    shm::with_prefix_mapped(file.as_raw_fd(), bytes, mempolicy_node_of).map_err(shm_io)?
}

/// Off Linux, a page's node cannot be read.
///
/// # Errors
///
/// Always returns [`NumaError::LibnumaMissing`]: NUMA placement is Linux-only.
#[cfg(not(target_os = "linux"))]
pub fn detect_numa_node_for_shm(_shm_path: &Path) -> Result<u32, NumaError> {
    Err(NumaError::LibnumaMissing)
}

/// Bind the memory at `addr..addr + bytes` to NUMA node `node` with
/// `mbind(2)`, moving pages already there (`MPOL_MF_MOVE | MPOL_MF_STRICT`).
///
/// Without `CAP_SYS_NICE` (`EPERM`) it binds the policy alone: pages already
/// faulted in stay where they are, and later faults land on `node`, which
/// for memory not yet touched is the same. Unlike thread pinning
/// ([`pin_thread_to_numa_node`]), the placement does not depend on which
/// thread touches a page first. On a single-node host it changes nothing.
///
/// # Errors
///
/// [`NumaError::NumaPin`] if `node >= 64` (the nodemask is one `u64`) or
/// `mbind(2)` refuses the binding (`EFAULT` for a bad range, `EINVAL` for a
/// bad policy), with the error of the first attempt;
/// [`NumaError::LibnumaMissing`] off Linux.
pub fn numa_bind_memory(addr: *mut u8, bytes: usize, node: u32) -> Result<(), NumaError> {
    #[cfg(target_os = "linux")]
    {
        // From <linux/mempolicy.h>; libc 0.2.186 does not expose them.
        const MPOL_MF_STRICT: libc::c_ulong = 1; // fail if pages can't be moved
        const MPOL_MF_MOVE: libc::c_ulong = 2; // try to move existing pages

        // One u64 of nodemask names nodes 0 to 63.
        if node >= 64 {
            return Err(NumaError::NumaPin {
                cpu: -1,
                node,
                reason: format!("node {} > 64; multi-word nodemask not implemented", node),
            });
        }
        let nodemask: [u64; 1] = [1u64 << node];

        // SAFETY: mbind only reads the `[addr, addr+bytes)` range the caller
        // mapped and the `nodemask` buffer we own; `maxnode` matches its
        // width. The kernel rejects invalid arguments with an errno rather
        // than touching memory.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_mbind,
                addr as *mut libc::c_void,
                bytes,
                libc::MPOL_BIND,
                nodemask.as_ptr(),
                64u64, // maxnode (one u64 = 64 bits)
                MPOL_MF_STRICT | MPOL_MF_MOVE,
            )
        };
        if rc == 0 {
            tracing::debug!(
                node,
                bytes,
                "numa_bind_memory: mbind succeeded (MOVE|STRICT)"
            );
            return Ok(());
        }

        // EPERM: no CAP_SYS_NICE to move pages, so bind the policy alone.
        let last_err = std::io::Error::last_os_error();
        if last_err.raw_os_error() == Some(libc::EPERM) {
            // SAFETY: same arguments as the first attempt, without the MOVE and
            // STRICT flags; policy-only binding touches no pages.
            let rc2 = unsafe {
                libc::syscall(
                    libc::SYS_mbind,
                    addr as *mut libc::c_void,
                    bytes,
                    libc::MPOL_BIND,
                    nodemask.as_ptr(),
                    64u64,
                    0u64, // no flags — policy-only, no page migration
                )
            };
            if rc2 == 0 {
                tracing::debug!(
                    node,
                    bytes,
                    "numa_bind_memory: mbind succeeded (policy-only, \
                     CAP_SYS_NICE unavailable — page migration skipped)"
                );
                return Ok(());
            }
        }

        Err(NumaError::NumaPin {
            cpu: -1,
            node,
            reason: format!(
                "mbind(addr={:p}, bytes={}, MPOL_BIND, node={}, MOVE|STRICT) failed: {}",
                addr, bytes, node, last_err,
            ),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (addr, bytes, node);
        Err(NumaError::LibnumaMissing)
    }
}

/// A second descriptor for what `fd` refers to, from `dup(2)`, for code
/// that forbids `unsafe`; the caller closes it, and closing one does not
/// close the other.
///
/// # Errors
///
/// [`NumaError::HugePageAlloc`] with the `dup(2)` error: `EBADF` for an `fd`
/// that is not open, `EMFILE` or `ENFILE` when descriptors run out.
pub fn dup_fd(fd: libc::c_int) -> Result<libc::c_int, NumaError> {
    // SAFETY: dup(2) takes any integer, fails with EBADF for one that is
    // not an open descriptor, and touches no memory of this process.
    let new_fd = unsafe { libc::dup(fd) };
    if new_fd < 0 {
        Err(NumaError::HugePageAlloc(format!(
            "dup({}) failed: {}",
            fd,
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(new_fd)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn allocate_shm_backing_without_numa_creates_a_page_aligned_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ring.shm");
        let cfg = ShmNumaConfig {
            shm_path: &path,
            capacity_bytes: 5000,
            page_size: PageSize::Regular,
            numa_node: None,
        };
        let backing = allocate_shm_backing(&cfg).expect("allocate");
        assert_eq!(backing.file().metadata().unwrap().len(), 8192);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn numa_bind_memory_rejects_node_64() {
        let mut byte = 0u8;
        match numa_bind_memory(&mut byte, 1, 64) {
            Err(NumaError::NumaPin { node: 64, .. }) => {}
            other => panic!("expected NumaPin for node 64, got {other:?}"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn numa_paths_report_missing_support_off_linux() {
        let mut byte = 0u8;
        assert!(matches!(
            numa_bind_memory(&mut byte, 1, 0),
            Err(NumaError::LibnumaMissing)
        ));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ring.shm");
        let cfg = ShmNumaConfig {
            shm_path: &path,
            capacity_bytes: 4096,
            page_size: PageSize::Regular,
            numa_node: Some(0),
        };
        assert!(matches!(
            allocate_shm_backing(&cfg),
            Err(NumaError::LibnumaMissing)
        ));
        assert!(matches!(
            detect_numa_node_for_shm(&path),
            Err(NumaError::LibnumaMissing)
        ));
    }

    #[test]
    fn page_size_bytes_round_trips() {
        assert_eq!(PageSize::Regular.bytes(), 4096);
        assert_eq!(PageSize::Huge2M.bytes(), 2 * 1024 * 1024);
        assert_eq!(PageSize::Huge1G.bytes(), 1024 * 1024 * 1024);
    }

    #[test]
    fn map_huge_flag_matches_kernel_constants() {
        assert_eq!(PageSize::Huge2M.map_huge_flag(), 21 << 26);
        assert_eq!(PageSize::Huge1G.map_huge_flag(), 30 << 26);
        assert_eq!(PageSize::Regular.map_huge_flag(), 0);
    }
}
