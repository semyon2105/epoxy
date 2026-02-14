use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{debug, error};

use crate::nss::PinCallback;

#[derive(Debug, Clone)]
pub struct PinInfo {
    pub cert: Option<String>,
    pub reason: String,
}

pub trait PinPrompt: Send + Sync {
    fn prompt_pin(&self, pin_info: PinInfo, token_name: String) -> Option<String>;
}

pub struct TtyPinPrompt;

impl PinPrompt for TtyPinPrompt {
    fn prompt_pin(&self, pin_info: PinInfo, token_name: String) -> Option<String> {
        if let Some(cert) = pin_info.cert {
            print!("{}: ", cert);
        }
        println!("{}", pin_info.reason);
        let prompt = format!("Enter PIN for {}: ", token_name);
        rpassword::prompt_password(prompt).ok()
    }
}

#[derive(Default)]
pub struct PinContext {
    pin_info: Mutex<Option<PinInfo>>,
}

#[derive(Debug, Error)]
pub enum PinContextError {
    #[error("mutex poisoned")]
    Locking,
}

pub struct PinContextGuard<'a> {
    context: &'a PinContext,
}

impl<'a> Drop for PinContextGuard<'a> {
    fn drop(&mut self) {
        let _ = self.context.set_pin_info(None);
    }
}

impl PinContext {
    pub fn pin_info(&self) -> Result<Option<PinInfo>, PinContextError> {
        let lock = self.pin_info.lock().map_err(|_| PinContextError::Locking)?;
        Ok(lock.clone())
    }

    pub fn with_pin_info(&self, pin_info: PinInfo) -> Result<PinContextGuard<'_>, PinContextError> {
        self.set_pin_info(Some(pin_info))?;

        Ok(PinContextGuard { context: self })
    }

    fn set_pin_info(&self, pin_info: Option<PinInfo>) -> Result<(), PinContextError> {
        let mut lock = self.pin_info.lock().map_err(|mut e| {
            **e.get_mut() = None;
            self.pin_info.clear_poison();
            PinContextError::Locking
        })?;

        *lock = pin_info;

        Ok(())
    }
}

pub struct PinProvider {
    context: Arc<PinContext>,
    prompter: Box<dyn PinPrompt>,
}

impl PinProvider {
    pub fn new(context: Arc<PinContext>, prompter: Box<dyn PinPrompt>) -> PinProvider {
        PinProvider { context, prompter }
    }
}

impl PinCallback for PinProvider {
    fn get_pin(&self, token_name: String) -> Option<String> {
        debug!("requesting PIN for {}", token_name);

        let pin_info = self
            .context
            .pin_info()
            .map_err(|e| {
                error!("PIN request error: {}", e);
            })
            .ok()?;

        let Some(pin_info) = pin_info else {
            error!("bug: info not provided for PIN request");
            return None;
        };

        self.prompter.prompt_pin(pin_info, token_name)
    }
}
