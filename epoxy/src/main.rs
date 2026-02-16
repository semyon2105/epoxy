mod config;
mod nss;
mod pin;
mod proto;
mod server;
#[cfg(feature = "ui-gtk")]
mod ui;
mod xmlsec;

use std::{io, rc::Rc, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use futures::{FutureExt, StreamExt, future::LocalBoxFuture};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
};
use tokio_debouncer::{DebounceMode, Debouncer};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_tungstenite::accept_async;
use tokio_util::sync::CancellationToken;
use tracing::{info, trace, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    config::{PinPromptKind, get_config},
    nss::{Nss, NssGlobals},
    pin::{PinContext, PinMethod, PinProvider, tty_pin_method},
    server::{Server, ServerConfig},
    xmlsec::XmlSec,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = get_config()?;

    init_tracing(&config.log).context("failed to initialize tracing")?;
    trace!("{:?}", config);

    let listener = get_listener(config.endpoint).await?;

    let pin_method_ct = CancellationToken::new();
    let (pin_prompt, pin_method_fut) = get_pin_method(config.pin_prompt, pin_method_ct.clone());
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
    let server_fut = serve(
        config.max_connections,
        config.max_idle_seconds,
        listener,
        server,
    );

    select! {
        _ = server_fut => pin_method_ct.cancel(),
        _ = pin_method_fut => (),
    }

    Ok(())
}

fn init_tracing(log_spec: &str) -> Result<()> {
    let env_filter = EnvFilter::from_str(log_spec).context("invalid log spec")?;
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    Ok(())
}

fn get_pin_method(pin_prompt: PinPromptKind, ct: CancellationToken) -> PinMethod {
    #[cfg(feature = "ui-gtk")]
    use crate::ui::ui_pin_method;

    match pin_prompt {
        config::PinPromptKind::Tty => tty_pin_method(ct),
        #[cfg(feature = "ui-gtk")]
        config::PinPromptKind::Ui => ui_pin_method(ct),
    }
}

async fn get_listener(endpoint: String) -> Result<TcpListener> {
    match endpoint.as_ref() {
        "sd-listen" => get_fd_listener(),
        endpoint => get_sockaddr_listener(endpoint).await,
    }
}

#[cfg(feature = "systemd")]
fn get_fd_listener() -> Result<TcpListener> {
    use anyhow::anyhow;
    use sd_notify::NotifyState;
    use std::os::fd::FromRawFd;

    let fd = sd_notify::listen_fds()
        .context("missing fds")?
        .next()
        .ok_or(anyhow!("missing fd"))?;

    let listener = TcpListener::from_std(unsafe { std::net::TcpListener::from_raw_fd(fd) })
        .context("failed to create listener from fd")?;

    let socket_addr = listener.local_addr().context("failed to get socket addr")?;
    info!("listening on {socket_addr} (fd {fd})");

    sd_notify::notify(true, &[NotifyState::Ready]).context("sd_notify failed")?;

    Ok(listener)
}

#[cfg(not(feature = "systemd"))]
fn get_fd_listener() -> Result<TcpListener> {
    use anyhow::anyhow;

    Err(anyhow!(
        "cannot listen on fd: \"systemd\" feature is disabled"
    ))
}

async fn get_sockaddr_listener(endpoint: &str) -> Result<TcpListener> {
    let listener = TcpListener::bind(endpoint)
        .await
        .context(format!("failed to listen on {}", endpoint))?;

    let socket_addr = listener.local_addr().context("failed to get socket addr")?;
    info!("listening on {socket_addr}");

    Ok(listener)
}

fn serve<'a>(
    max_connections: u8,
    max_idle_seconds: u64,
    listener: TcpListener,
    server: Rc<Server<'a>>,
) -> LocalBoxFuture<'a, ()> {
    let timeout = if max_idle_seconds == 0 {
        Duration::MAX
    } else {
        Duration::from_secs(max_idle_seconds)
    };

    let idle_debouncer = Debouncer::new(timeout, DebounceMode::Trailing);
    idle_debouncer.trigger();

    let server_fut = TcpListenerStream::new(listener)
        .map({
            let idle_debouncer = idle_debouncer.clone();
            move |conn| {
                idle_debouncer.clone().trigger();
                handle_conn(server.clone(), conn)
            }
        })
        .buffer_unordered(max_connections as usize)
        .collect::<()>();

    async move {
        select! {
            _ = idle_debouncer.ready() => info!("no new connections accepted within {max_idle_seconds} seconds, shutting down..."),
            _ = server_fut => (),
        }
    }
    .boxed_local()
}

async fn handle_conn<'a>(server: Rc<Server<'a>>, conn: Result<TcpStream, io::Error>) {
    let stream = match conn {
        Ok(stream) => stream,
        Err(e) => {
            warn!("failed to accept connection: {e}");
            return;
        }
    };

    let Ok(peer_addr) = stream.peer_addr() else {
        warn!("failed to accept connection: no peer address");
        return;
    };

    let Ok(ws_stream) = accept_async(stream).await else {
        warn!("failed to accept connection from {peer_addr}: WebSocket handshake error");
        return;
    };

    info!("connection accepted: {peer_addr}");

    match server.run(ws_stream).await {
        Ok(()) => {
            info!("connection closed: {peer_addr}");
        }
        Err(e) => {
            warn!("connection terminated: {peer_addr} {e}")
        }
    }
}
