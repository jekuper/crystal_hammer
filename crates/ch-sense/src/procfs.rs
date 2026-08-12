//! Direct /proc parsers. No external process is ever spawned here.

/// Parse /proc into the process list. Implemented at M3.
pub fn read_processes() -> ch_common::Result<Vec<crate::Process>> {
    Ok(Vec::new())
}

/// Parse /proc/net/{tcp,udp,packet,raw,...} into sockets. Implemented at M3/M4.
pub fn read_sockets() -> ch_common::Result<Vec<crate::Socket>> {
    Ok(Vec::new())
}
