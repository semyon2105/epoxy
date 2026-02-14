//! Open PIN dialog with mock data

use std::thread;

use anyhow::{Context, Error};
use epoxy::{pin::PinInfo, ui};
use tracing::info;

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let (tx, rx) = ui::new_pin_channel();
    let (reply_tx, reply_rx) = oneshot::channel();

    let pin_info = PinInfo {
        cert: Some("John Doe 012345678 Sign".into()),
        reason: "Sign form (unidentified)".into(),
    };

    let token_name = "My Token".into();

    tx.blocking_send((pin_info, token_name, reply_tx))
        .context("failed to send PIN request")?;

    thread::spawn(|| ui::run("dev.semyon.epoxy.test", rx));

    let pin = reply_rx.recv().context("failed to receive PIN")?;
    let masked_pin = pin.map(|p| str::repeat("*", p.len()));
    info!("received PIN: {:?}", masked_pin);

    Ok(())
}
