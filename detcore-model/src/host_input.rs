/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The host identity of a file a guest opened.
//!
//! Hermit maps each host inode it sees to a deterministic one in the order it
//! first sees them, so a host file that is REPLACED while a run is going (a
//! package manager rewriting `/etc/ld.so.cache` between the opens of two
//! guest processes, for example) gives that run one more inode than the other
//! run, and every later inode number differs. `hermit run --verify` then
//! reports a divergence that the guest did not cause. Each verification run
//! therefore records one [`HostInputRecord`] per host file the guest opens.
//! Detcore reports each open to its global state
//! ([`crate::config::Config::record_host_inputs`]), which writes the run's
//! records to a side file ([`crate::config::Config::host_input_log`]) when the
//! run ends, never part of the compared log. On a divergence the two runs'
//! records are compared to name such a change.
//!
//! A run that writes a record meant to be reproduced later (a
//! `--record-preemptions-to` schedule, or a `--summary-json` summary) also
//! keeps a [`HostInputSet`]: each regular host file the guest opened, with the
//! identity its first open found, and a digest of the set. A run that replays
//! such a schedule compares the files it opened against the set when it ends
//! and reports each one that changed ([`HostInputChange`]): Hermit does not
//! make a changing filesystem deterministic, so a replay that reads different
//! host files can diverge, and it then says why.
//!
//! Nothing here touches a file while the guest runs, beyond the `stat` and the
//! `readlink` of its own descriptor that every open already costs: the guest
//! could observe a read, as an inotify watch on the file's directory does. A
//! file's bytes are hashed when the run ends, after the guest's processes
//! have exited, and only where the file is the one its open found
//! ([`HostReopen`]).

use std::path::Path;

use serde::Deserialize;
use serde::Serialize;

/// The host's identity for a file at the moment the guest opened it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct HostFileIdentity {
    /// The host `st_dev`.
    pub dev: u64,
    /// The host `st_ino`.
    pub ino: u64,
    /// The host `st_size`.
    pub size: i64,
    /// The host `st_mtime`, seconds.
    pub mtime_sec: i64,
    /// The host `st_mtime`, nanoseconds.
    pub mtime_nsec: i64,
}

impl HostFileIdentity {
    /// The identity in a host `struct stat`.
    pub fn from_stat(stat: &libc::stat) -> Self {
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
            size: stat.st_size,
            mtime_sec: stat.st_mtime,
            mtime_nsec: stat.st_mtime_nsec,
        }
    }
}

impl std::fmt::Display for HostFileIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dev:ino {}:{}:{} size {} mtime {}.{:09}",
            libc::major(self.dev),
            libc::minor(self.dev),
            self.ino,
            self.size,
            self.mtime_sec,
            self.mtime_nsec
        )
    }
}

/// One host file a guest opened: the path it named, made absolute against its
/// working directory or directory descriptor, the host identity of the file
/// the open reached, and the open itself, as the thread (`dtid`) and that
/// thread's syscall number (`syscall`, the `finish syscall #N` of the run's
/// log) that made it. A path that is not UTF-8 is recorded lossily.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostInputRecord {
    pub path: String,
    pub dtid: u64,
    pub syscall: u64,
    #[serde(flatten)]
    pub identity: HostFileIdentity,
    /// The SHA-256 (lowercase hex) of the file's bytes, read when the run
    /// ended, where Detcore could reach the file then and found it unchanged
    /// since the open ([`HostReopen`], [`HostInput::content`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Whether the kernel opened the file for an exec, as the new image or
    /// its program interpreter, rather than the guest by an open call. Such a
    /// record has no open in the log, so the verification pattern walk
    /// leaves it out; a [`HostInputSet`] keeps it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exec: bool,
    /// Whether the open reached a kernel object ([`is_kernel_object`]) by
    /// the descriptor's own path, whatever the guest spelled (`/etc/mtab`
    /// names `/proc/self/mounts`). A [`HostInputSet`] leaves it out, as it
    /// leaves out a path spelled under `/proc`, `/sys` or `/dev`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub kernel_object: bool,
    /// Whether the open reached something other than a regular file: a
    /// directory, a FIFO, a socket or a device. A [`HostInputSet`] leaves it
    /// out. Hermit has no bytes of it to compare, and its identity changes
    /// whenever it is made again: a directory Hermit makes for each run (the
    /// guest's private `/tmp`) has a new inode in every run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub non_regular: bool,
    /// Where the tool can find the file again when the run ends, to hash its
    /// bytes then. Never written: the path is the tool's view, which another
    /// run need not share.
    #[serde(skip)]
    pub reopen: Option<HostReopen>,
}

/// How Detcore finds a host file the guest opened again when the run ends:
/// the path the tool's own `readlink` of the guest's descriptor (or of its
/// `exe` link, or the mapping `/proc/<pid>/maps` shows) gave, which is the
/// tool's view of the file, and the file's change time at the open. The file
/// is hashed only if it still has the identity and change time its open found:
/// a file rewritten in place gets a new change time even where its size and
/// modification time are set back. Only two writes within one tick of the
/// filesystem's clock, the second after the open, can go unseen. The same gate
/// makes a path from another view safe: where Detcore runs inside the guest,
/// the path is the guest's view, and the global state, which hashes, may see
/// another file there (after a `chroot`, say); that file has another identity,
/// so it is not hashed.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct HostReopen {
    pub path: std::path::PathBuf,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

impl HostReopen {
    /// The reopening of the file at `path` (the tool's view) whose `stat` at
    /// the open was `stat`.
    pub fn new(path: std::path::PathBuf, stat: &libc::stat) -> Self {
        Self {
            path,
            ctime_sec: stat.st_ctime,
            ctime_nsec: stat.st_ctime_nsec,
        }
    }

    /// Whether `stat`, taken when the run ends, shows the file the open
    /// found: the same identity and change time.
    pub fn unchanged(&self, identity: &HostFileIdentity, stat: &libc::stat) -> bool {
        HostFileIdentity::from_stat(stat) == *identity
            && (stat.st_ctime, stat.st_ctime_nsec) == (self.ctime_sec, self.ctime_nsec)
    }
}

/// A path the guest itself rebound in its file namespace during the run:
/// renamed to or from, linked, unlinked, made as a symlink, node or directory,
/// removed as a directory, or opened to create (see
/// [`crate::config::Config::record_host_inputs`]). Made absolute as an open's
/// path is. A host file whose path, or a directory above it, the guest
/// rebound may have been replaced by the guest, so such a change is never
/// named as a host input change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMutationRecord {
    pub mutated: String,
}

/// The last line of a complete host-input log: how many records, of both
/// kinds, precede it. A log without it, or with another count, is incomplete.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostInputLogEnd {
    pub records: u64,
}

/// One host file in a [`HostInputSet`]: its path and the identity the run's
/// first open of that path found.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostInput {
    pub path: String,
    #[serde(flatten)]
    pub identity: HostFileIdentity,
    /// The SHA-256 (lowercase hex) of the file's bytes: present for a file of
    /// at most [`HOST_INPUT_CONTENT_LIMIT`] bytes on a backend whose tool can
    /// see the guest's descriptors, read when the run ended, where the file
    /// was still the one that open found ([`HostReopen`]). The guest sees a
    /// host file's bytes and size, not its host inode or times (Hermit
    /// virtualizes those), so where both runs have it, the content decides
    /// whether the file changed ([`host_input_changed`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// The largest file whose bytes Detcore hashes for a [`HostInput`]: a larger
/// one is compared by its identity alone, so that a run whose guest opens big
/// data files does not pay to read them again at its end.
pub const HOST_INPUT_CONTENT_LIMIT: u64 = 32 << 20;

/// Whether `now` shows a different file than `recorded`, for the same path:
/// other bytes, where both runs hashed them, and otherwise another identity.
/// A file rewritten with the same bytes (as a package manager's `ldconfig`
/// does) is therefore not a change where its content was hashed.
pub fn host_input_changed(recorded: &HostInput, now: &HostInput) -> bool {
    match (&recorded.content, &now.content) {
        (Some(recorded), Some(now)) => recorded != now,
        _ => recorded.identity != now.identity,
    }
}

/// The host files one run's guest opened, for a later run that reproduces it
/// to compare against: one [`HostInput`] per path, sorted by path, and a
/// digest of the set, so that two runs can be compared by one string. The
/// digest is the SHA-256 (lowercase hex) of one line per file: its path and
/// the SHA-256 of its bytes where they were hashed, otherwise its identity.
/// So it agrees with [`host_input_changed`]: two runs that read the same
/// bytes at the same paths get the same digest whatever the files' inodes
/// and times. A path is left out when it is not absolute, names a kernel
/// object ([`is_kernel_object`], also by the descriptor's own path,
/// [`HostInputRecord::kernel_object`]), is not a regular file
/// ([`HostInputRecord::non_regular`]), or was rebound by the guest itself
/// ([`guest_rebound`]): those can change between runs without the host's
/// files changing.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostInputSet {
    pub digest: String,
    pub files: Vec<HostInput>,
    /// The kinds of file behind the guest's standard descriptors when the
    /// run began ([`StdioKinds`]). Not part of [`Self::digest`], which follows
    /// the files alone. Absent where the run did not look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdio: Option<StdioKinds>,
}

impl HostInputSet {
    /// The entry this set holds for `path`. A set read from a file is
    /// searched as its files lie; [`Self::normalized`] sorts it first.
    pub fn file(&self, path: &str) -> Option<&HostInput> {
        self.files
            .binary_search_by(|file| file.path.as_str().cmp(path))
            .ok()
            .map(|index| &self.files[index])
    }

    /// This set with its files sorted by path and one entry per path (the
    /// first), as a run writes it, whatever a file it was read from held.
    pub fn normalized(mut self) -> Self {
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
        self.files
            .dedup_by(|later, earlier| later.path == earlier.path);
        self
    }
}

/// A host file that differs between a recorded run and the run that
/// reproduces it ([`host_input_changed`]): other bytes, or, where either run
/// could not hash them, another identity (replaced, or modified in size or
/// time). The reproduction may read other bytes than the recorded run did,
/// and diverge where it does.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostInputChange {
    pub path: String,
    pub recorded: HostFileIdentity,
    pub now: HostFileIdentity,
}

impl std::fmt::Display for HostInputChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "host input {} changed since the recording ({} then, {} now); the run may diverge where the guest reads it",
            self.path, self.recorded, self.now
        )
    }
}

/// The kind of file behind one of the guest's standard descriptors. A guest
/// can tell them apart (`fstat`, `isatty`, and calls whose result depends on
/// the kind: `fsync` fails with `EINVAL` on a pipe and succeeds on a file, and
/// `lseek` fails with `ESPIPE` on a pipe), so a replay whose stdio kinds
/// differ from its recording's may run differently where the guest checks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StdioKind {
    /// A regular file.
    File,
    /// A pipe or FIFO.
    Pipe,
    /// A socket.
    Socket,
    /// A terminal.
    Tty,
    /// A character device that is not a terminal, such as `/dev/null`.
    CharDevice,
    /// A block device.
    BlockDevice,
    /// A directory.
    Directory,
    /// No open descriptor.
    Closed,
}

impl StdioKind {
    /// The kind of an open descriptor whose `st_mode` is `mode`, with
    /// `terminal` whether it is a terminal (`isatty`).
    pub fn from_mode(mode: libc::mode_t, terminal: bool) -> Self {
        match mode & libc::S_IFMT {
            libc::S_IFREG => Self::File,
            libc::S_IFIFO => Self::Pipe,
            libc::S_IFSOCK => Self::Socket,
            libc::S_IFCHR if terminal => Self::Tty,
            libc::S_IFCHR => Self::CharDevice,
            libc::S_IFBLK => Self::BlockDevice,
            libc::S_IFDIR => Self::Directory,
            // `S_IFLNK` cannot be an open descriptor's kind.
            _ => Self::File,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::File => "a regular file",
            Self::Pipe => "a pipe",
            Self::Socket => "a socket",
            Self::Tty => "a terminal",
            Self::CharDevice => "a character device",
            Self::BlockDevice => "a block device",
            Self::Directory => "a directory",
            Self::Closed => "closed",
        }
    }
}

/// The kinds of file behind the guest's stdin, stdout and stderr when a run
/// began.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StdioKinds {
    pub stdin: StdioKind,
    pub stdout: StdioKind,
    pub stderr: StdioKind,
}

impl StdioKinds {
    /// The descriptors whose kind differs between `recorded` and `now`, in
    /// descriptor order.
    pub fn changes(recorded: &Self, now: &Self) -> Vec<StdioChange> {
        [
            (0, recorded.stdin, now.stdin),
            (1, recorded.stdout, now.stdout),
            (2, recorded.stderr, now.stderr),
        ]
        .into_iter()
        .filter(|(_, recorded, now)| recorded != now)
        .map(|(fd, recorded, now)| StdioChange { fd, recorded, now })
        .collect()
    }
}

/// A standard descriptor whose kind differs between a recorded run and the
/// run that reproduces it ([`StdioKinds::changes`]).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StdioChange {
    /// 0, 1 or 2.
    pub fd: u8,
    pub recorded: StdioKind,
    pub now: StdioKind,
}

impl std::fmt::Display for StdioChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self.fd {
            0 => "stdin",
            1 => "stdout",
            _ => "stderr",
        };
        write!(
            f,
            "{name} (fd {}) was {} in the recording and is {} now; the run may diverge where the guest checks it (fstat, isatty, fsync, lseek)",
            self.fd,
            self.recorded.describe(),
            self.now.describe()
        )
    }
}

/// The marker that begins the stderr line a reproducing run prints for each
/// [`HostInputChange`]. A harness greps for it, as for
/// `HERMIT_SKID_OVERSHOOT`; keep it stable.
pub const HOST_INPUT_CHANGED_SINCE_RECORDING_MARKER: &str =
    "HERMIT_HOST_INPUT_CHANGED_SINCE_RECORDING";

/// Whether `path` names a kernel object under `/proc`, `/sys` or `/dev`
/// rather than a host input file: its metadata is not file content, and
/// Hermit virtualizes those trees separately.
pub fn is_kernel_object(path: &str) -> bool {
    ["/proc", "/sys", "/dev"].iter().any(|root| {
        path == *root
            || path
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Whether the guest may have rebound `path`, or a directory above it, in its
/// file namespace: one of `mutated` ([`HostMutationRecord`] paths) is `path`
/// or an ancestor of it. Detcore reports `/`, the ancestor of every absolute
/// path, for a change whose path it could not establish. A path that is not
/// absolute cannot be matched against those changes at all, so it counts as
/// rebound too.
pub fn guest_rebound<'a>(mutated: impl IntoIterator<Item = &'a String>, path: &str) -> bool {
    let path = Path::new(path);
    !path.is_absolute()
        || mutated
            .into_iter()
            .any(|rebound| path.starts_with(Path::new(rebound)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(ino: u64, size: i64) -> HostFileIdentity {
        HostFileIdentity {
            dev: 33,
            ino,
            size,
            mtime_sec: 1_700_000_000,
            mtime_nsec: 5,
        }
    }

    fn set(files: &[(&str, HostFileIdentity)]) -> HostInputSet {
        HostInputSet {
            stdio: None,
            digest: String::new(),
            files: files
                .iter()
                .map(|(path, identity)| HostInput {
                    path: (*path).to_owned(),
                    identity: *identity,
                    content: None,
                })
                .collect(),
        }
    }

    /// A descriptor's kind follows its mode, and a character device is a
    /// terminal only when it says so. A replay names each descriptor whose
    /// kind changed, in descriptor order. A set without stdio kinds is
    /// written as before, and one with them round-trips.
    #[test]
    fn stdio_kinds_name_each_changed_descriptor() {
        assert_eq!(
            StdioKind::from_mode(libc::S_IFREG | 0o644, false),
            StdioKind::File
        );
        assert_eq!(StdioKind::from_mode(libc::S_IFIFO, false), StdioKind::Pipe);
        assert_eq!(StdioKind::from_mode(libc::S_IFCHR, true), StdioKind::Tty);
        assert_eq!(
            StdioKind::from_mode(libc::S_IFCHR, false),
            StdioKind::CharDevice
        );
        let recorded = StdioKinds {
            stdin: StdioKind::CharDevice,
            stdout: StdioKind::Pipe,
            stderr: StdioKind::File,
        };
        let now = StdioKinds {
            stdin: StdioKind::Closed,
            stderr: StdioKind::Pipe,
            ..recorded
        };
        assert!(StdioKinds::changes(&recorded, &recorded).is_empty());
        let changes = StdioKinds::changes(&recorded, &now);
        assert_eq!(
            changes,
            vec![
                StdioChange {
                    fd: 0,
                    recorded: StdioKind::CharDevice,
                    now: StdioKind::Closed,
                },
                StdioChange {
                    fd: 2,
                    recorded: StdioKind::File,
                    now: StdioKind::Pipe,
                },
            ]
        );
        assert_eq!(
            changes[1].to_string(),
            "stderr (fd 2) was a regular file in the recording and is a pipe now; the run may \
             diverge where the guest checks it (fstat, isatty, fsync, lseek)"
        );
        let without = set(&[]);
        assert!(!serde_json::to_string(&without).unwrap().contains("stdio"));
        let with = HostInputSet {
            stdio: Some(now),
            ..set(&[])
        };
        let json = serde_json::to_string(&with).unwrap();
        assert!(json.contains(r#""stderr":"pipe""#), "{json}");
        assert_eq!(serde_json::from_str::<HostInputSet>(&json).unwrap(), with);
    }

    #[test]
    fn a_rebound_ancestor_or_a_relative_path_counts_as_rebound() {
        let mutated = vec!["/work".to_owned()];
        assert!(guest_rebound(&mutated, "/work/out.txt"));
        assert!(guest_rebound(&mutated, "/work"));
        assert!(!guest_rebound(&mutated, "/workspace/in.txt"));
        assert!(guest_rebound(&mutated, "relative.txt"));
        assert!(guest_rebound(&["/".to_owned()], "/etc/ld.so.cache"));
    }

    #[test]
    fn a_set_finds_each_file_by_its_path() {
        let recorded = set(&[
            ("/etc/ld.so.cache", identity(9, 36887)),
            ("/lib64/libc.so.6", identity(10, 2_000_000)),
        ]);
        assert_eq!(
            recorded.file("/etc/ld.so.cache").map(|file| file.identity),
            Some(identity(9, 36887))
        );
        assert_eq!(
            recorded.file("/lib64/libc.so.6").map(|file| file.identity),
            Some(identity(10, 2_000_000))
        );
        assert_eq!(recorded.file("/etc"), None);
    }

    #[test]
    fn hashed_content_decides_over_identity() {
        let file = |ino: u64, content: Option<&str>| HostInput {
            path: "/etc/ld.so.cache".to_owned(),
            identity: identity(ino, 36887),
            content: content.map(str::to_owned),
        };
        // Rewritten with the same bytes: a new inode, no change.
        assert!(!host_input_changed(
            &file(9, Some("aa")),
            &file(11, Some("aa"))
        ));
        // Same inode and size, other bytes: a change.
        assert!(host_input_changed(
            &file(9, Some("aa")),
            &file(9, Some("bb"))
        ));
        // Either side unhashed: the identity decides.
        assert!(host_input_changed(&file(9, None), &file(11, Some("aa"))));
        assert!(!host_input_changed(&file(9, Some("aa")), &file(9, None)));
    }

    #[test]
    fn the_change_line_names_the_path_and_both_identities() {
        let change = HostInputChange {
            path: "/etc/ld.so.cache".to_owned(),
            recorded: identity(9, 36887),
            now: identity(11, 36839),
        };
        let line = change.to_string();
        assert!(line.starts_with("host input /etc/ld.so.cache changed since the recording"));
        assert!(line.contains("size 36887"), "{line}");
        assert!(line.contains("size 36839"), "{line}");
    }
}
