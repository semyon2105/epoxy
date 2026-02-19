//! Open PIN dialog with mock data

use anyhow::Error;
use epoxy::{pin::PinInfo, ui};
use tokio_util::sync::CancellationToken;
use tracing::info;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let pin_method_ct = CancellationToken::new();
    let (pin_prompt, pin_method_fut) = ui::ui_pin_method(pin_method_ct.clone());

    let pin_info = PinInfo {
        cert: Some("John Doe 012345678 Sign".into()),
        reason: "Sign form (unidentified)".into(),
    };
    let token_name = "My Token".into();

    let pin = pin_prompt.prompt_pin(&pin_info, token_name);

    let masked_pin = pin.map(|p| str::repeat("*", p.len()));
    info!("received PIN: {:?}", masked_pin);

    pin_method_ct.cancel();
    pin_method_fut.await;

    Ok(())
}
