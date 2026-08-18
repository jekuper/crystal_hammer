// ch-firewall-common/src/lib.rs
#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockedIpKey {
    pub prefix_len: u32,   // for LpmTrie
    pub addr_be: u32,      // IPv4, big-endian
}