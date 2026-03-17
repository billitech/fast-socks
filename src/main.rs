#![forbid(unsafe_code)]
#[macro_use]
extern crate log;

use anyhow::Context;
use fast_socks5::{
    ReplyError, Result, Socks5Command, SocksError,
    server::{DnsResolveHelper as _, Socks5ServerProtocol, run_tcp_proxy, run_udp_proxy},
};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tokio::net::TcpListener;
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::Semaphore;
use tokio::task;
use tokio::time::sleep;
use tokio::time::timeout;

/// # How to use it:
///
/// Listen on a local address without authentication:
///     `$ RUST_LOG=debug cargo run -- --listen-addr 127.0.0.1:1337 no-auth`
///
/// Listen on a local address with basic username/password authentication:
///     `$ RUST_LOG=debug cargo run -- --listen-addr 127.0.0.1:1337 password --username admin --password password`
///
/// With UDP support (requires setting public-addr):
///     `$ RUST_LOG=debug cargo run -- --listen-addr 127.0.0.1:1337 --allow-udp --public-addr 127.0.0.1 password --username admin --password password`
#[derive(Debug, StructOpt)]
#[structopt(
    name = "socks5-server",
    about = "A simple implementation of a SOCKS5 server."
)]
struct Opt {
    /// Bind on address, e.g. `127.0.0.1:1080`
    #[structopt(short, long)]
    pub listen_addr: String,

    /// External IP address to be sent in reply packets (required for UDP)
    #[structopt(long)]
    pub public_addr: Option<std::net::IpAddr>,

    /// Request timeout in seconds
    #[structopt(short = "t", long, default_value = "10")]
    pub request_timeout: u64,

    /// Maximum time to wait for a client to finish the SOCKS handshake
    #[structopt(long, default_value = "10")]
    pub handshake_timeout: u64,

    /// Maximum number of concurrent client sessions to allow
    #[structopt(long, default_value = "256")]
    pub max_connections: usize,

    /// Maximum lifetime in seconds for an established TCP proxy session
    #[structopt(long, default_value = "1800")]
    pub session_timeout: u64,

    /// Authentication mode (subcommand)
    #[structopt(subcommand, name = "auth")]
    pub auth: AuthMode,

    /// Skip the authentication handshake (not RFC-compliant)
    #[structopt(short = "k", long)]
    pub skip_auth: bool,

    /// Allow UDP proxying (requires public-addr)
    #[structopt(short = "U", long)]
    pub allow_udp: bool,
}

/// Authentication modes: No authentication or password-based.
#[derive(StructOpt, Debug, PartialEq)]
enum AuthMode {
    NoAuth,
    Password {
        #[structopt(short, long)]
        username: String,
        #[structopt(short, long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    spawn_socks_server().await
}

async fn spawn_socks_server() -> Result<()> {
    // Leak the options to get a 'static reference.
    let opt: &'static Opt = Box::leak(Box::new(Opt::from_args()));

    if opt.allow_udp && opt.public_addr.is_none() {
        return Err(SocksError::ArgumentInputError(
            "Can't allow UDP if public-addr is not set",
        ));
    }
    if opt.skip_auth && opt.auth != AuthMode::NoAuth {
        return Err(SocksError::ArgumentInputError(
            "Can't use skip-auth flag and authentication together.",
        ));
    }

    let listener = TcpListener::bind(&opt.listen_addr).await?;
    let connection_limit = Arc::new(Semaphore::new(opt.max_connections));
    info!("Listening for SOCKS connections at {}", &opt.listen_addr);

    loop {
        match listener.accept().await {
            Ok((socket, client_addr)) => {
                let permit = match connection_limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(
                            "Rejecting connection from {} because {} active sessions are already in use",
                            client_addr, opt.max_connections
                        );
                        continue;
                    }
                };

                spawn_and_log_error(serve_socks5(opt, socket, client_addr, permit));
            }
            Err(err) => {
                error!("Accept error: {:?}", err);
                if err.raw_os_error() == Some(24) {
                    sleep(Duration::from_millis(250)).await;
                }
            }
        }
    }
}

async fn serve_socks5(
    opt: &Opt,
    socket: tokio::net::TcpStream,
    client_addr: std::net::SocketAddr,
    _permit: OwnedSemaphorePermit,
) -> Result<(), SocksError> {
    let handshake = async {
        let (proto, cmd, target_addr) = match &opt.auth {
            AuthMode::NoAuth if opt.skip_auth => {
                Socks5ServerProtocol::skip_auth_this_is_not_rfc_compliant(socket)
            }
            AuthMode::NoAuth => Socks5ServerProtocol::accept_no_auth(socket).await?,
            AuthMode::Password { username, password } => {
                Socks5ServerProtocol::accept_password_auth(socket, |user, pass| {
                    user == *username && pass == *password
                })
                .await?
                .0
            }
        }
        .read_command()
        .await?
        .resolve_dns()
        .await?;

        Ok::<_, SocksError>((proto, cmd, target_addr))
    };

    let (proto, cmd, target_addr) = timeout(Duration::from_secs(opt.handshake_timeout), handshake)
        .await
        .map_err(|_| {
            SocksError::Other(anyhow::anyhow!(
                "client handshake from {} timed out after {}s",
                client_addr,
                opt.handshake_timeout
            ))
        })??;

    match cmd {
        Socks5Command::TCPConnect => {
            timeout(
                Duration::from_secs(opt.session_timeout),
                run_tcp_proxy(proto, &target_addr, opt.request_timeout, false),
            )
            .await
            .map_err(|_| {
                SocksError::Other(anyhow::anyhow!(
                    "tcp proxy session for {} timed out after {}s",
                    client_addr,
                    opt.session_timeout
                ))
            })??;
        }
        Socks5Command::UDPAssociate if opt.allow_udp => {
            let reply_ip = opt.public_addr.context("invalid reply ip")?;
            run_udp_proxy(proto, &target_addr, None, reply_ip, None).await?;
        }
        _ => {
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            return Err(ReplyError::CommandNotSupported.into());
        }
    };

    info!("Closed session for {}", client_addr);
    Ok(())
}

fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        if let Err(err) = fut.await {
            error!("{:#}", &err);
        }
    })
}
