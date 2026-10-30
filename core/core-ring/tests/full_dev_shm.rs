// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! A reader never takes SIGBUS from a full `/dev/shm`.
//!
//! A creator names and sizes its object before it reserves the pages, and
//! publishes the header only after. A reader that mapped the object in
//! that window and touched its header page would be killed with SIGBUS on
//! a full `/dev/shm`, since the tmpfs cannot supply the page; so opens read
//! the header with `pread`, which allocates nothing, and map only a ring
//! whose header is published, and `from_fd` reserves a fresh region before
//! it touches it. This covers `open`, `open_existing` and a reader racing
//! `create_exclusive`. Each way in runs in a child process, so that a
//! signal kills the child and not the test:
//! first against an object sized and never reserved on a full `/dev/shm`,
//! then against a creator whose every attempt gets `NoSpace`. Each must
//! return an error, or wait and then return one, and never be killed.
//!
//! The test fills `/dev/shm`, so it runs only where `/dev/shm` is at most
//! 16 MiB, as in the Linux test container run with an 8 MB `/dev/shm`;
//! anywhere larger it says why it checks nothing and passes.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]

#[cfg(target_os = "linux")]
mod linux {
    use core_ring::{PulseRing, RingError, HEADER_SIZE, PULSE_SIZE};
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    /// The environment variables that make the test binary a child.
    const ROLE: &str = "PMS_FULL_SHM_ROLE";
    const NAME: &str = "PMS_FULL_SHM_NAME";
    /// This test's path, for the child to run it alone.
    const TEST: &str = "linux::opens_on_a_full_dev_shm_fail_and_are_never_killed";
    /// Slots in the rings here: one page of shared memory.
    const SLOTS: u64 = 8;

    /// Total and free bytes of the tmpfs behind `/dev/shm`, or `None` where
    /// there is none with a size limit to measure.
    #[allow(clippy::unnecessary_cast)] // the statvfs field types differ between targets
    fn dev_shm_space() -> Option<(u64, u64)> {
        let path = CString::new("/dev/shm").unwrap();
        let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: statvfs reads the NUL-terminated path and writes one
        // `statvfs` into the buffer, which is read only when it returns 0.
        if unsafe { libc::statvfs(path.as_ptr(), st.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: statvfs returned 0, so it initialised the buffer.
        let st = unsafe { st.assume_init() };
        let unit = st.f_frsize as u64;
        let total = st.f_blocks as u64 * unit;
        (total > 0).then(|| (total, st.f_bavail as u64 * unit))
    }

    /// A file in `/dev/shm` holding every free page, removed on drop.
    struct Filler(std::path::PathBuf);

    impl Filler {
        fn fill() -> Self {
            use std::os::unix::io::AsRawFd;
            let path =
                std::path::PathBuf::from(format!("/dev/shm/fsr-fill-{:x}", std::process::id()));
            let file = std::fs::File::create(&path).expect("create the filler");
            let filler = Filler(path);
            let mut len: libc::off_t = 0;
            let mut step = libc::off_t::MAX;
            for _ in 0..64 {
                let (_, free) = dev_shm_space().expect("measure /dev/shm");
                if free == 0 {
                    return filler;
                }
                let add = step.min(free as libc::off_t);
                // SAFETY: posix_fallocate reads only its integer arguments
                // and allocates storage for the file `file` keeps open.
                match unsafe { libc::posix_fallocate(file.as_raw_fd(), len, add) } {
                    0 => len += add,
                    libc::EINTR => {}
                    libc::ENOSPC if add > 4096 => step = add / 2,
                    e => panic!("filling /dev/shm failed at {len} bytes: errno {e}"),
                }
            }
            panic!("/dev/shm still had room after filling {len} bytes");
        }
    }

    impl Drop for Filler {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// An object under `name` as a creator holds it between sizing it and
    /// reserving its pages: sized for a ring of [`SLOTS`] slots, and none
    /// of its pages allocated. Unlinked on drop.
    struct HalfMade(CString);

    impl HalfMade {
        fn new(name: &str) -> Self {
            let cname = CString::new(name).unwrap();
            // SAFETY: `cname` is a valid NUL-terminated string for the call.
            let fd = unsafe {
                libc::shm_open(
                    cname.as_ptr(),
                    libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                    0o600,
                )
            };
            assert!(fd >= 0, "shm_open {name} failed");
            let len = HEADER_SIZE + SLOTS as usize * PULSE_SIZE;
            // SAFETY: sizes the object opened above, allocating none of its
            // pages, and closes the descriptor, which nothing else holds.
            unsafe {
                assert_eq!(libc::ftruncate(fd, len as libc::off_t), 0, "ftruncate");
                libc::close(fd);
            }
            Self(cname)
        }
    }

    impl Drop for HalfMade {
        fn drop(&mut self) {
            // SAFETY: unlinks the name `new` created.
            unsafe { libc::shm_unlink(self.0.as_ptr()) };
        }
    }

    /// A name unique to this process and `tag`, at most 30 bytes.
    fn shm_name(tag: &str) -> String {
        let name = format!("/fsr-{tag}-{:x}", std::process::id());
        assert!(name.len() <= 30, "{name} is longer than macOS allows");
        let _ = PulseRing::unlink(&name);
        name
    }

    /// Run `role` on `name` in a child process, returning how it ended and
    /// what it printed.
    fn child(role: &str, name: &str) -> (ExitStatus, String) {
        let out = Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(ROLE, role)
            .env(NAME, name)
            .stdin(Stdio::null())
            .output()
            .expect("run the child");
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        (out.status, text)
    }

    /// Assert that a child ended of its own accord with status 0.
    fn assert_survived(role: &str, status: ExitStatus, text: &str) {
        match status.signal() {
            Some(libc::SIGBUS) => panic!("{role} was killed by SIGBUS:\n{text}"),
            Some(signal) => panic!("{role} was killed by signal {signal}:\n{text}"),
            None => assert_eq!(status.code(), Some(0), "{role} failed:\n{text}"),
        }
    }

    /// What a child does, as `ROLE` names it; the exit status says whether
    /// the open came out as it must. A ring that opens is read, which a
    /// ring whose pages do not exist would answer with SIGBUS.
    fn run_role(role: &str, name: &str) -> i32 {
        let opened = |what: &str, result: Result<PulseRing, RingError>| match result {
            Ok(ring) => {
                let _ = ring.read_slot(0);
                println!("role {what}: opened a ring it must refuse");
                1
            }
            Err(e) => {
                println!("role {what}: refused: {e}");
                0
            }
        };
        match role {
            "open" => opened("open", PulseRing::open(name, SLOTS)),
            "open_existing" => opened("open_existing", PulseRing::open_existing(name)),
            "create_or_open" => opened("create_or_open", PulseRing::create_or_open(name, SLOTS)),
            "create" => opened("create", PulseRing::create(name, SLOTS)),
            "from_fd" => {
                let cname = CString::new(name).unwrap();
                // SAFETY: `cname` is a valid NUL-terminated string.
                let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0) };
                assert!(fd >= 0, "shm_open {name}");
                match PulseRing::from_fd("fsr-from-fd", fd, SLOTS, false, false) {
                    Err(RingError::NoSpace { errno, .. }) => {
                        println!("role from_fd: refused: no space, errno {errno}");
                        0
                    }
                    other => opened("from_fd", other),
                }
            }
            "spin" => spin(name),
            other => panic!("unknown role {other}"),
        }
    }

    /// Open `name` again and again while a creator on a full `/dev/shm`
    /// makes and abandons it, until the opens have met the creator's
    /// object a few times or five seconds pass. Prints what the opens met.
    fn spin(name: &str) -> i32 {
        let started = Instant::now();
        let (mut absent, mut met, mut opened, mut other) = (0u64, 0u64, 0u64, 0u64);
        while (met < 3 || started.elapsed() < Duration::from_millis(500))
            && started.elapsed() < Duration::from_secs(5)
        {
            let results = [PulseRing::open(name, SLOTS), PulseRing::open_existing(name)];
            for result in results {
                match result {
                    Err(RingError::Open(libc::ENOENT)) => absent += 1,
                    // The creator's object, not yet sized, or sized and with
                    // no header yet.
                    Err(RingError::RegionTooSmall { have: 0, .. })
                    | Err(RingError::LayoutMismatch {
                        field: "magic",
                        have: 0,
                        ..
                    }) => met += 1,
                    Ok(ring) => {
                        let _ = ring.read_slot(0);
                        opened += 1;
                    }
                    Err(_) => other += 1,
                }
            }
        }
        println!("spin: absent={absent} met={met} opened={opened} other={other}");
        0
    }

    #[test]
    fn opens_on_a_full_dev_shm_fail_and_are_never_killed() {
        if let Ok(role) = std::env::var(ROLE) {
            let code = run_role(&role, &std::env::var(NAME).unwrap());
            std::io::stdout().flush().unwrap();
            std::process::exit(code);
        }
        const SMALL: u64 = 16 << 20;
        let Some((total, _)) = dev_shm_space() else {
            eprintln!("no size-limited /dev/shm to measure; nothing checked");
            return;
        };
        if total > SMALL {
            eprintln!(
                "/dev/shm is {total} bytes; the test fills it only when it is at most \
                 {SMALL} bytes, so nothing is checked"
            );
            return;
        }

        // Every way of opening a ring by name, and `from_fd`, meets an
        // object sized and never reserved, with no page left to give it.
        let name = shm_name("half");
        let half_made = HalfMade::new(&name);
        let filler = Filler::fill();
        for role in [
            "open",
            "open_existing",
            "create_or_open",
            "create",
            "from_fd",
        ] {
            let (status, text) = child(role, &name);
            assert_survived(role, status, &text);
            assert!(
                text.contains(&format!("role {role}: refused")),
                "{role} did not run or was not refused:\n{text}"
            );
        }
        drop(half_made);

        // A reader racing a creator whose every attempt runs out of room.
        let name = shm_name("race");
        let mut reader = Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(ROLE, "spin")
            .env(NAME, &name)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the reader");
        let (mut refused, mut created) = (0u64, 0u64);
        while reader.try_wait().expect("poll the reader").is_none() {
            match PulseRing::create_exclusive(&name, SLOTS) {
                Err(RingError::NoSpace { .. }) => refused += 1,
                Ok(ring) => {
                    created += 1;
                    drop(ring);
                }
                Err(e) => panic!("the creator failed otherwise: {e}"),
            }
        }
        let out = reader.wait_with_output().expect("the reader's output");
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        assert_survived("a reader racing create_exclusive", out.status, &text);
        assert_eq!(created, 0, "a ring was made in a full /dev/shm");
        assert!(refused > 0, "the creator never ran");
        let counts = text
            .lines()
            .find_map(|line| line.split_once("spin: ").map(|(_, counts)| counts))
            .unwrap_or_else(|| panic!("the reader printed no counts:\n{text}"));
        let met = counts
            .split(' ')
            .find_map(|c| c.strip_prefix("met="))
            .and_then(|n| n.parse::<u64>().ok())
            .expect("the reader's count of the creator's objects");
        assert!(
            met > 0,
            "the reader never met the creator's object:\n{text}"
        );
        eprintln!("the creator was refused {refused} times; the reader saw {counts}");
        drop(filler);
    }
}
