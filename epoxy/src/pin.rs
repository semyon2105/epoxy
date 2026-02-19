use futures::{
    FutureExt,
    future::{self, LocalBoxFuture},
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::nss;

pub type PinMethod = (Arc<dyn PinPrompt>, LocalBoxFuture<'static, ()>);

pub fn tty_pin_method(_: CancellationToken) -> PinMethod {
    (Arc::new(TtyPinPrompt), future::pending().boxed_local())
}

#[derive(Debug, Clone)]
pub struct PinInfo {
    pub cert: Option<String>,
    pub reason: String,
}

pub trait PinPrompt: Send + Sync {
    fn prompt_pin(&self, pin_info: &PinInfo, token_name: String) -> Option<String>;
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

pub struct PinContext {
    pin_prompt: Arc<dyn PinPrompt>,
    pin_info: PinInfo,
}

impl PinContext {
    pub fn new(pin_prompt: Arc<dyn PinPrompt>, pin_info: PinInfo) -> PinContext {
        PinContext {
            pin_prompt,
            pin_info,
        }
    }
}

impl nss::PinCallback for PinContext {
    fn get_pin(&self, token_name: String) -> Option<String> {
        debug!("requesting PIN for {}", token_name);
        self.pin_prompt.prompt_pin(&self.pin_info, token_name)
    }
}
