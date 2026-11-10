//! Check a handle's claims against the real platforms.
//!
//! ```text
//! cargo run -p libveritas_crossverify --features fetch --example verify -- \
//!     buffrr@bitcoin github=buffrr,id:41967894 x=_buffrr,tweet:2100240557159112799
//! ```
//!
//! Each claim is `<record key>=<value>,<value>,...`, the way the record set
//! stores it. Notary keys to trust go in `--notary <hex>`.

use futures::StreamExt;
use libveritas_crossverify::fetch::{Checked, Verifier};
use libveritas_crossverify::{Claim, Context};
use std::time::Instant;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let Some(handle) = args.next() else {
        eprintln!("usage: verify <handle> <key>=<value>[,<value>...] ... [--notary <hex>]");
        std::process::exit(2);
    };
    let mut ctx = Context::default();
    let mut claims = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--notary" {
            let key = args.next().and_then(|h| {
                (0..h.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok())
                    .collect::<Option<Vec<u8>>>()?
                    .try_into()
                    .ok()
            });
            match key {
                Some(k) => ctx.trusted_notaries.push(k),
                None => {
                    eprintln!("--notary needs a 32-byte hex key");
                    std::process::exit(2);
                }
            }
            continue;
        }
        let Some((key, values)) = arg.split_once('=') else {
            eprintln!("{arg:?}: expected <key>=<value>,...");
            std::process::exit(2);
        };
        let values: Vec<&str> = values.split(',').collect();
        match Claim::new(key, &values) {
            Ok(c) => claims.push(c),
            Err(e) => eprintln!("{key}: {e}"),
        }
    }

    let verifier = Verifier::new(ctx);
    let start = Instant::now();
    // Print each result as it arrives, not when the slowest one is done.
    let mut results = match verifier.verify_each(&handle, &claims) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("invalid handle: {e}");
            std::process::exit(2);
        }
    };
    while let Some(Checked { index, outcome }) = results.next().await {
        let claim = &claims[index];
        println!(
            "{:>5} ms  {:<10} {:<28} {outcome}",
            start.elapsed().as_millis(),
            claim.platform,
            claim.account
        );
    }
}
