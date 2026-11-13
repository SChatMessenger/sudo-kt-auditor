//! The Sudo key transparency auditor (sudoproto.md §6.4, §10.14).
//!
//! It walks a relay's public audit proofs from the first epoch (or from where
//! it stopped), and for every epoch:
//! 1. fetches `GET /v1/kt/audit/{epoch}`: the epoch's signed head, then akd's
//!    append-only proof from the previous epoch;
//! 2. checks the head with `sudo-kt` (signature with the relay's public head
//!    key, and the same root as any head already accepted for that epoch) and
//!    that it is the epoch it asked for;
//! 3. checks the proof from the previous root to this root (`akd`'s own audit
//!    check);
//! 4. records (epoch, root, sth_hash, signed head) in its log.
//!
//! The latest head goes through `sudo-kt`'s full §6.2 checks first (10-minute
//! limit, no older epoch, no second root for a checked epoch). Any failure
//! stops the run and keeps the relay's exact answers as evidence. All
//! cryptography is in released libraries; this crate fetches, orders and
//! records.

#![forbid(unsafe_code)]

use protobuf::Message;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use sudo_kt::{HEAD_LEN, HeadState, SignedHead};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The largest answer the auditor reads (a proof for one epoch).
pub const MAX_ANSWER: usize = 64 * 1024 * 1024;
/// How long one answer may take before the run stops.
pub const TIMEOUT: Duration = Duration::from_secs(120);
/// The pause between epochs: at most about 545 requests a minute, under the
/// relay's 600 a minute per network (§10.14).
pub const PACE: Duration = Duration::from_millis(110);

/// Why the auditor stopped. `Evidence` failures mean the relay broke a key
/// transparency rule; the rest are ordinary problems (network, files).
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// The relay address is not a local `http://` address (no TLS yet).
    BadRelayUrl,
    /// The relay could not be reached in time or its answer was not complete
    /// HTTP.
    Network(String),
    /// The relay answered with this HTTP status.
    Status(u16),
    /// The state folder could not be used.
    State(String),
    /// The latest head is more than 10 minutes from this computer's clock:
    /// either the relay froze its directory, or this computer's clock is
    /// wrong. The head is kept in `evidence`.
    StaleHead { evidence: PathBuf },
    /// The relay broke a rule. `what` says which; `evidence` is the folder
    /// holding the relay's exact answers.
    Evidence { what: String, evidence: PathBuf },
}

/// One checked epoch, as the log records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    pub epoch: u64,
    pub root: [u8; 32],
    pub sth_hash: [u8; 32],
    pub head: Vec<u8>,
}

/// What a run did.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    /// Epochs checked in this run (first, last), if any.
    pub checked: Option<(u64, u64)>,
    /// The relay's latest epoch and root.
    pub latest: (u64, [u8; 32]),
}

/// Lower-case hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|p| u8::from_str_radix(p, 16).ok()))
        .collect()
}

/// Exactly 64 hex digits.
pub fn key_from_hex(s: &str) -> Option<[u8; 32]> {
    unhex(s)?.try_into().ok()
}

/// `host:port` for a relay given as `http://host:port`. Only this computer
/// (no TLS yet).
pub fn relay_addr(url: &str) -> Result<String, Failure> {
    let rest = url
        .strip_prefix("http://")
        .ok_or(Failure::BadRelayUrl)?
        .trim_end_matches('/');
    let host = match rest.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => return Err(Failure::BadRelayUrl),
    };
    if !matches!(host, "localhost" | "127.0.0.1" | "[::1]") || rest.contains('/') {
        return Err(Failure::BadRelayUrl);
    }
    Ok(rest.to_owned())
}

/// A plain HTTP/1.1 GET: (status, body), within [`TIMEOUT`].
pub async fn http_get(addr: &str, path: &str) -> Result<(u16, Vec<u8>), Failure> {
    http_get_within(addr, path, TIMEOUT).await
}

async fn http_get_within(
    addr: &str,
    path: &str,
    limit: Duration,
) -> Result<(u16, Vec<u8>), Failure> {
    tokio::time::timeout(limit, get(addr, path))
        .await
        .unwrap_or_else(|_| Err(Failure::Network("the relay did not answer in time".into())))
}

async fn get(addr: &str, path: &str) -> Result<(u16, Vec<u8>), Failure> {
    let net = |e: std::io::Error| Failure::Network(e.kind().to_string());
    let mut stream = TcpStream::connect(addr).await.map_err(net)?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.map_err(net)?;
    let mut raw = Vec::new();
    (&mut stream)
        .take(u64::try_from(MAX_ANSWER + 4096).unwrap_or(u64::MAX))
        .read_to_end(&mut raw)
        .await
        .map_err(net)?;
    let bad = || Failure::Network("not a complete HTTP answer".into());
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(bad)?;
    let head = std::str::from_utf8(raw.get(..split).ok_or_else(bad)?).map_err(|_| bad())?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.strip_prefix("HTTP/1.1 "))
        .and_then(|l| l.get(..3))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(bad)?;
    let body = raw.get(split + 4..).ok_or_else(bad)?.to_vec();
    // The body must be exactly as long as the relay says, so a cut answer is
    // never checked as if it were whole (and never blamed on the relay).
    let mut length = None;
    for (k, v) in lines.filter_map(|l| l.split_once(':')) {
        if k.eq_ignore_ascii_case("transfer-encoding") {
            return Err(bad());
        }
        if k.eq_ignore_ascii_case("content-length") {
            length = Some(v.trim().parse::<usize>().map_err(|_| bad())?);
        }
    }
    if length != Some(body.len()) {
        return Err(bad());
    }
    Ok((status, body))
}

/// The auditor's state folder: `heads.log` (one checked epoch per line:
/// epoch, root, sth_hash, signed head, all hex) and `evidence/` (one folder
/// per failed run, never overwritten). Only one run at a time may use it.
pub struct Store {
    dir: PathBuf,
    /// Held while the store is open; the system lets go if the run dies.
    _lock: fs::File,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self, Failure> {
        let state = |e: std::io::Error| Failure::State(e.to_string());
        fs::create_dir_all(dir.join("evidence")).map_err(state)?;
        let lock = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(dir.join("lock"))
            .map_err(state)?;
        lock.try_lock().map_err(|e| match e {
            fs::TryLockError::WouldBlock => {
                Failure::State("another run is using this state folder".into())
            }
            fs::TryLockError::Error(e) => state(e),
        })?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: lock,
        })
    }

    fn log(&self) -> PathBuf {
        self.dir.join("heads.log")
    }

    /// Every checked epoch, in order. The log must hold epochs 1, 2, 3, …
    /// with no gap, or it is refused (a damaged state is never trusted).
    pub fn checked(&self) -> Result<Vec<Checked>, Failure> {
        let text = match fs::read_to_string(self.log()) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Failure::State(e.to_string())),
        };
        let bad = |n: usize| Failure::State(format!("heads.log line {n} is damaged"));
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let mut f = line.split(' ');
            let (Some(e), Some(r), Some(s), Some(h), None) =
                (f.next(), f.next(), f.next(), f.next(), f.next())
            else {
                return Err(bad(i + 1));
            };
            let c = Checked {
                epoch: e.parse().map_err(|_| bad(i + 1))?,
                root: unhex(r)
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| bad(i + 1))?,
                sth_hash: unhex(s)
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| bad(i + 1))?,
                head: unhex(h).ok_or_else(|| bad(i + 1))?,
            };
            if c.epoch != u64::try_from(i).map_err(|_| bad(i + 1))? + 1 {
                return Err(bad(i + 1));
            }
            out.push(c);
        }
        Ok(out)
    }

    fn append(&self, c: &Checked) -> Result<(), Failure> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log())
            .map_err(|e| Failure::State(e.to_string()))?;
        writeln!(
            f,
            "{} {} {} {}",
            c.epoch,
            hex(&c.root),
            hex(&c.sth_hash),
            hex(&c.head)
        )
        .and_then(|()| f.sync_all())
        .map_err(|e| Failure::State(e.to_string()))
    }

    /// Keeps the relay's exact answers in a new folder `evidence/<now>`
    /// (`<now>-2`, … if it exists): earlier evidence is never overwritten.
    fn keep(&self, now: u64, files: &[(&str, &[u8])]) -> Result<PathBuf, Failure> {
        let state = |e: std::io::Error| Failure::State(format!("could not keep evidence: {e}"));
        let mut n = 1u32;
        let folder = loop {
            let name = if n == 1 {
                now.to_string()
            } else {
                format!("{now}-{n}")
            };
            let p = self.dir.join("evidence").join(name);
            match fs::create_dir(&p) {
                Ok(()) => break p,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 1000 => n += 1,
                Err(e) => return Err(state(e)),
            }
        };
        for (name, bytes) in files {
            fs::write(folder.join(name), bytes).map_err(state)?;
        }
        Ok(folder)
    }

    fn evidence(&self, now: u64, files: &[(&str, &[u8])], what: &str) -> Failure {
        match self.keep(now, files) {
            Ok(evidence) => Failure::Evidence {
                what: what.to_owned(),
                evidence,
            },
            Err(e) => e,
        }
    }
}

/// The rule a head broke, in words (the checks are sudo-kt's).
fn head_rule(e: sudo_kt::Error) -> String {
    match e {
        sudo_kt::Error::HeadLength | sudo_kt::Error::HeadSignature => {
            "the head's signature does not verify".into()
        }
        sudo_kt::Error::HeadEpochTime => {
            "the head's times are impossible (epoch_time after head_time)".into()
        }
        sudo_kt::Error::HeadOlderEpoch => {
            "the latest epoch is lower than one already checked: the log shrank".into()
        }
        sudo_kt::Error::SplitView => {
            "the relay signed a different root for an epoch already checked: two directories (§6.4)"
                .into()
        }
        other => format!("the head breaks a rule ({other:?})"),
    }
}

/// akd's own append-only check from `from` to `to` (§6.4).
async fn proof_ok(from: [u8; 32], to: [u8; 32], proof: &[u8]) -> bool {
    let Ok(p) = akd::proto::specs::types::AppendOnlyProof::parse_from_bytes(proof) else {
        return false;
    };
    let Ok(p) = akd::AppendOnlyProof::try_from(&p) else {
        return false;
    };
    akd::auditor::audit_verify::<sudo_kt::Kt>(vec![from, to], p)
        .await
        .is_ok()
}

/// One run: from the last checked epoch to the relay's latest (§10.14).
/// `now` is the auditor's clock (Unix seconds), for the latest head's age
/// and the evidence folder's name.
pub async fn run(
    relay: &str,
    head_key: &[u8; 32],
    store: &Store,
    now: u64,
) -> Result<Report, Failure> {
    let addr = relay_addr(relay)?;
    let done = store.checked()?;
    // The log must be this relay's and undamaged: every line matches its own
    // head, signed with this head key.
    for c in &done {
        let ok = HeadState::new()
            .check_by_hash(head_key, &c.head, &c.sth_hash)
            .is_ok_and(|h| h.epoch == c.epoch && h.root_hash == c.root);
        if !ok {
            return Err(Failure::State(format!(
                "heads.log epoch {} does not match its signed head for this head key (damaged, or another relay's log)",
                c.epoch
            )));
        }
    }
    let mut heads = HeadState::from_accepted(done.iter().map(|c| (c.epoch, c.root)));
    // The latest head: sudo-kt's §6.2 checks against everything checked so far.
    let (status, latest_bytes) = http_get(&addr, "/v1/kt/latest").await?;
    if status != 200 {
        return Err(Failure::Status(status));
    }
    let latest_file = ("latest-head.bin", latest_bytes.as_slice());
    let latest = match heads.accept(head_key, &latest_bytes, now) {
        Ok(h) => *h.head(),
        Err(sudo_kt::Error::HeadTime) => {
            return Err(Failure::StaleHead {
                evidence: store.keep(now, &[latest_file])?,
            });
        }
        Err(e) => return Err(store.evidence(now, &[latest_file], &head_rule(e))),
    };
    let last = done.last().map_or(0, |c| c.epoch);
    let mut prev_root = done.last().map_or([0u8; 32], |c| c.root);
    let mut first = None;
    for epoch in last + 1..=latest.epoch {
        if first.is_some() {
            tokio::time::sleep(PACE).await;
        }
        let (status, body) = http_get(&addr, &format!("/v1/kt/audit/{epoch}")).await?;
        let name = format!("epoch-{epoch}.bin");
        let files = [latest_file, (name.as_str(), body.as_slice())];
        if status == 404 {
            // The signed latest head says this epoch exists (§10.14).
            return Err(store.evidence(
                now,
                &files,
                &format!(
                    "the relay signed epoch {} but has no proof for epoch {epoch}",
                    latest.epoch
                ),
            ));
        }
        if status != 200 {
            return Err(Failure::Status(status));
        }
        let Some((head_bytes, proof)) = body.split_at_checked(HEAD_LEN) else {
            return Err(store.evidence(now, &files, "the answer is shorter than a head"));
        };
        // Signature, and the same root as the latest head if this is its
        // epoch (sudo-kt's split-view check).
        let head = SignedHead::parse(head_bytes)
            .and_then(|p| heads.check_by_hash(head_key, head_bytes, &p.sth_hash()));
        let head = match head {
            Ok(h) => h,
            Err(e) => return Err(store.evidence(now, &files, &head_rule(e))),
        };
        if head.epoch != epoch {
            return Err(store.evidence(
                now,
                &files,
                "the head is for another epoch than the one asked for",
            ));
        }
        if !proof_ok(prev_root, head.root_hash, proof).await {
            return Err(store.evidence(
                now,
                &files,
                "the append-only proof does not verify: the relay rewrote its directory",
            ));
        }
        store.append(&Checked {
            epoch,
            root: head.root_hash,
            sth_hash: head.sth_hash(),
            head: head_bytes.to_vec(),
        })?;
        prev_root = head.root_hash;
        first.get_or_insert(epoch);
    }
    Ok(Report {
        checked: first.map(|f| (f, latest.epoch)),
        latest: (latest.epoch, latest.root_hash),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_relays() {
        assert_eq!(
            relay_addr("http://127.0.0.1:8080/").unwrap(),
            "127.0.0.1:8080"
        );
        assert_eq!(relay_addr("http://localhost:1").unwrap(), "localhost:1");
        for bad in [
            "https://127.0.0.1:8080",
            "http://example.com:80",
            "http://127.0.0.1",
            "http://127.0.0.1:80/x",
            "127.0.0.1:80",
        ] {
            assert_eq!(relay_addr(bad), Err(Failure::BadRelayUrl), "{bad}");
        }
    }

    #[test]
    fn keys_are_exactly_64_hex_digits() {
        assert_eq!(key_from_hex(&"ab".repeat(32)), Some([0xab; 32]));
        assert!(key_from_hex(&"ab".repeat(31)).is_none());
        assert!(key_from_hex(&format!("+f{}", "ab".repeat(31))).is_none());
    }

    /// A one-shot server that sends `answer` as is.
    async fn raw_server(answer: &'static [u8]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(answer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn cut_or_broken_answers_are_refused() {
        let ok = raw_server(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc").await;
        assert_eq!(http_get(&ok, "/").await, Ok((200, b"abc".to_vec())));
        let cut = raw_server(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nabc").await;
        assert!(matches!(
            http_get(&cut, "/").await,
            Err(Failure::Network(_))
        ));
        let long = raw_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabc").await;
        assert!(matches!(
            http_get(&long, "/").await,
            Err(Failure::Network(_))
        ));
        let junk = raw_server(b"hello").await;
        assert!(matches!(
            http_get(&junk, "/").await,
            Err(Failure::Network(_))
        ));
        // No length: a dropped connection would look like a whole answer.
        let no_length = raw_server(b"HTTP/1.1 200 OK\r\n\r\nabc").await;
        assert!(matches!(
            http_get(&no_length, "/").await,
            Err(Failure::Network(_))
        ));
        let chunked = raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
        )
        .await;
        assert!(matches!(
            http_get(&chunked, "/").await,
            Err(Failure::Network(_))
        ));
    }

    #[tokio::test]
    async fn a_silent_relay_stops_the_run() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            // Accepts and never answers.
            let held = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(held);
        });
        let r = http_get_within(&addr, "/", Duration::from_millis(200)).await;
        assert_eq!(
            r,
            Err(Failure::Network("the relay did not answer in time".into()))
        );
    }

    #[test]
    fn one_run_at_a_time() {
        let dir = std::env::temp_dir().join(format!("sudo-kt-auditor-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = Store::open(&dir).unwrap();
        assert!(matches!(Store::open(&dir), Err(Failure::State(_))));
        drop(first);
        assert!(Store::open(&dir).is_ok(), "free again after the run");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_is_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("sudo-kt-auditor-ev-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        let a = store.keep(5, &[("x.bin", b"first")]).unwrap();
        let b = store.keep(5, &[("x.bin", b"second")]).unwrap();
        assert_ne!(a, b);
        assert_eq!(fs::read(a.join("x.bin")).unwrap(), b"first");
        assert_eq!(fs::read(b.join("x.bin")).unwrap(), b"second");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_log_is_refused() {
        let dir = std::env::temp_dir().join(format!("sudo-kt-auditor-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        let c = |epoch| Checked {
            epoch,
            root: [epoch as u8; 32],
            sth_hash: [1; 32],
            head: vec![2; HEAD_LEN],
        };
        store.append(&c(1)).unwrap();
        store.append(&c(2)).unwrap();
        assert_eq!(store.checked().unwrap(), vec![c(1), c(2)]);
        store.append(&c(4)).unwrap(); // a gap
        assert!(matches!(store.checked(), Err(Failure::State(_))));
        let _ = fs::remove_dir_all(&dir);
    }
}
