//! `sudo-kt-auditor`: checks a Sudo relay's key directory (§6.4, §10.14).
//!
//! ```text
//! sudo-kt-auditor --relay http://127.0.0.1:8080 --head-key <64 hex> [--state DIR]
//! ```
//!
//! `--head-key` is the relay's public head key (the relay prints it at
//! start; apps have it built in). The state folder (default
//! `./.sudo-kt-auditor`) keeps `heads.log`, every head checked so far, which
//! anyone can publish and compare, and `evidence/` if the relay broke a rule.
//!
//! Exit status: 0 all checked; 2 the relay broke a key transparency rule
//! (evidence kept); 3 the latest head is more than 10 minutes from this
//! computer's clock (the relay froze its directory, or this clock is wrong;
//! head kept); 1 anything else (usage, network, files).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use sudo_kt_auditor::{Failure, Store, hex, key_from_hex, run};

fn usage() -> &'static str {
    "usage: sudo-kt-auditor --relay http://127.0.0.1:PORT --head-key <64 hex> [--state DIR]\n\nThe relay must run on this computer (no TLS yet)."
}

struct Args {
    relay: String,
    head_key: [u8; 32],
    state: PathBuf,
}

fn parse(args: &[String]) -> Option<Args> {
    let mut it = args.iter().skip(1);
    let (mut relay, mut key, mut state) = (None, None, PathBuf::from(".sudo-kt-auditor"));
    while let Some(a) = it.next() {
        match a.as_str() {
            "--relay" => relay = Some(it.next()?.clone()),
            "--head-key" => key = Some(key_from_hex(it.next()?)?),
            "--state" => state = PathBuf::from(it.next()?),
            _ => return None,
        }
    }
    Some(Args {
        relay: relay?,
        head_key: key?,
        state,
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().collect();
    let Some(args) = parse(&raw) else {
        eprintln!("{}", usage());
        return ExitCode::from(1);
    };
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => {
            eprintln!("sudo-kt-auditor: this computer's clock is before 1970");
            return ExitCode::from(1);
        }
    };
    let store = match Store::open(&args.state) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    match run(&args.relay, &args.head_key, &store, now).await {
        Ok(report) => {
            match report.checked {
                Some((a, b)) => println!("checked epochs {a} to {b}: every proof verifies"),
                None => println!("nothing new to check"),
            }
            println!(
                "latest epoch {} root {}",
                report.latest.0,
                hex(&report.latest.1)
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn fail(e: &Failure) -> ExitCode {
    match e {
        Failure::Evidence { what, evidence } => {
            eprintln!("sudo-kt-auditor: THE RELAY BROKE A RULE: {what}");
            eprintln!("evidence kept in {}", evidence.display());
            ExitCode::from(2)
        }
        Failure::StaleHead { evidence } => {
            eprintln!(
                "sudo-kt-auditor: the relay's latest head is more than 10 minutes from this computer's clock."
            );
            eprintln!(
                "Check this computer's clock first; if it is right, the relay froze its key directory."
            );
            eprintln!("head kept in {}", evidence.display());
            ExitCode::from(3)
        }
        Failure::BadRelayUrl => {
            eprintln!("sudo-kt-auditor: the relay must be http://localhost:PORT (no TLS yet)");
            ExitCode::from(1)
        }
        Failure::Network(why) => {
            eprintln!("sudo-kt-auditor: cannot reach the relay ({why})");
            ExitCode::from(1)
        }
        Failure::Status(code) => {
            eprintln!("sudo-kt-auditor: the relay answered HTTP {code}");
            ExitCode::from(1)
        }
        Failure::State(why) => {
            eprintln!("sudo-kt-auditor: state folder problem: {why}");
            ExitCode::from(1)
        }
    }
}
