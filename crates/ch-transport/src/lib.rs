pub mod server;
pub mod client;
pub mod proxy;

pub use server::{serve, CommandExecutor};
pub use client::{connect, Target, ClientCommandExecutor};

pub use client::proxy_hop;
pub use proxy::Hop;

#[cfg(unix)]
pub(crate) fn set_tcp_keepalive(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    unsafe {
        let optval: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        #[cfg(target_os = "linux")]
        {
            let keepidle: libc::c_int = 30; // Probe after 30 seconds of idle
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPIDLE,
                &keepidle as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    Ok(())
}