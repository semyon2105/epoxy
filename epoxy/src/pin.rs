use futures::{
    FutureExt,
    future::{self, LocalBoxFuture},
};
use tokio_util::sync::CancellationToken;

use crate::nss::{PinInfo, PinPrompt};

pub type PinMethod = (Box<dyn PinPrompt>, LocalBoxFuture<'static, ()>);

pub fn tty_pin_method(_: CancellationToken) -> PinMethod {
    (Box::new(TtyPinPrompt), future::pending().boxed_local())
}

pub struct TtyPinPrompt;

impl PinPrompt for TtyPinPrompt {
    fn prompt_pin(&self, pin_info: &PinInfo, token_name: String) -> Option<String> {
        if let Some(cert) = &pin_info.cert {
            print!("{}: ", cert);
        }
        println!("{}", pin_info.reason);
        let prompt = format!("Enter PIN for {}: ", token_name);
        rpassword::prompt_password(prompt).ok()
    }
}
