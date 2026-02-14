mod config;
mod nss;
mod pin;
mod proto;
mod server;
#[cfg(feature = "ui-gtk")]
mod ui;
mod xmlsec;

use std::{rc::Rc, str::FromStr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use futures::{
    FutureExt, StreamExt,
    future::{self, LocalBoxFuture},
};
use pin::PinPrompt;
use tokio::{
    io,
    net::{TcpListener, TcpStream},
};
use tokio_listener::{Listener, SystemOptions, UserOptions};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_tungstenite::accept_async;
use tracing::{info, trace, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    config::{PinPromptKind, get_config},
    nss::{Nss, NssGlobals},
    pin::{PinContext, PinProvider},
    server::{Server, ServerConfig},
    xmlsec::XmlSec,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = get_config()?;

    init_tracing(&config.log).context("failed to initialize tracing")?;
    trace!("{:?}", config);

    let listener = get_listener(config.endpoint).await?;

    let (pin_prompt, pin_prompt_fut) = get_pin_prompt(config.pin_prompt);
    let pin_context = Arc::new(PinContext::default());
    let pin_provider = Box::new(PinProvider::new(pin_context.clone(), pin_prompt));

    let nss_globals = NssGlobals::get_or_init(pin_provider);
    let nss = Rc::new(
        Nss::initialize(nss_globals, config.nssdb_path).context("failed to initialize NSS")?,
    );
    let xmlsec = XmlSec::initialize(nss.clone()).context("failed to initialize xmlsec")?;

    let server_config = ServerConfig {
        allow_soft_tokens: config.allow_soft_tokens,
    };
    let server = Rc::new(Server::new(server_config, pin_context, nss, xmlsec));

    let server_fut = serve(config.max_connections, listener, server);

    match pin_prompt_fut {
        None => {
            server_fut.await;
        }
        Some(pin_prompt_fut) => {
            future::select_all([server_fut, pin_prompt_fut]).await;
        }
    };

    Ok(())
}

fn init_tracing(log_spec: &str) -> Result<()> {
    let env_filter = EnvFilter::from_str(log_spec).context("invalid log spec")?;
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    Ok(())
}

type PinPromptStack = (Box<dyn PinPrompt>, Option<LocalBoxFuture<'static, ()>>);

fn get_pin_prompt(pin_prompt: PinPromptKind) -> PinPromptStack {
    match pin_prompt {
        config::PinPromptKind::Tty => (Box::new(pin::TtyPinPrompt), None),
        #[cfg(feature = "ui-gtk")]
        config::PinPromptKind::Ui => ui_pin_prompt(),
    }
}

#[cfg(feature = "ui-gtk")]
fn ui_pin_prompt() -> PinPromptStack {
    use futures::FutureExt;
    use tokio::task;
    use tracing::{debug, error};

    let app_id = "dev.semyon.epoxy";
    let (pin_tx, pin_rx) = ui::new_pin_channel();
    let pin_prompt = Box::new(pin_tx);
    let ui_fut = task::spawn_blocking(|| ui::run(app_id, pin_rx)).map(|result| match result {
        Ok(exit_code) if exit_code.get() != 0 => {
            error!("UI exited with code {}", exit_code.get())
        }
        Ok(_) => {
            debug!("UI exited with code 0")
        }
        Err(e) => {
            error!("UI exited with error: {e}")
        }
    });
    (pin_prompt, Some(ui_fut.boxed_local()))
}

async fn get_listener(endpoint: String) -> Result<TcpListener> {
    let listener_addr = endpoint
        .parse()
        .map_err(|e| anyhow!("invalid endpoint: {e}"))?;
    let system_opts = SystemOptions::default();
    let user_opts = UserOptions::default();

    let listener = Listener::bind(&listener_addr, &system_opts, &user_opts)
        .await
        .context(format!("failed to bind to {}", endpoint))?
        .try_into_tcp_listener()
        .map_err(|_| anyhow!("{endpoint} is not a TCP socket"))?;

    match listener.local_addr() {
        Ok(socket_addr) => info!("listening on {}", socket_addr),
        Err(_) => info!("listening on {}", endpoint),
    }

    Ok(listener)
}

fn serve<'a>(
    max_connections: u8,
    listener: TcpListener,
    server: Rc<Server<'a>>,
) -> LocalBoxFuture<'a, ()> {
    TcpListenerStream::new(listener)
        .map(move |conn| handle_conn(server.clone(), conn))
        .buffer_unordered(max_connections as usize)
        .collect::<()>()
        .boxed_local()
}

async fn handle_conn<'a>(server: Rc<Server<'a>>, conn: Result<TcpStream, io::Error>) {
    let Ok(stream) = conn else {
        warn!("failed to accept connection");
        return;
    };

    let Ok(peer_addr) = stream.peer_addr() else {
        warn!("failed to accept connection: no peer address");
        return;
    };

    let Ok(ws_stream) = accept_async(stream).await else {
        warn!("failed to accept connection: WebSocket handshake error");
        return;
    };

    info!("connection accepted: {}", peer_addr);

    match server.run(ws_stream).await {
        Ok(()) => {
            info!("connection closed: {peer_addr}");
        }
        Err(e) => {
            warn!("connection terminated: {e}")
        }
    }
}
