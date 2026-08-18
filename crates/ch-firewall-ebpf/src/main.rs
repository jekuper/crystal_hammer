// ch-firewall-ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::{HashMap, LpmTrie},
    programs::TcContext,
};
use ch_firewall_common::BlockedIpKey;
use network_types::{eth::{EthHdr, EtherType}, ip::Ipv4Hdr};

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

#[map]
static ALLOWED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static BLOCKED_IPS: LpmTrie<BlockedIpKey, u8> = LpmTrie::with_max_entries(1024, 0);

#[classifier]
pub fn ch_firewall(ctx: TcContext) -> i32 {
    match try_filter(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => TC_ACT_OK, // fail-open on parse errors — flip to TC_ACT_SHOT if you want fail-closed
    }
}

fn try_filter(ctx: &TcContext) -> Result<i32, ()> {
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    if eth.ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_OK); // only filtering v4 for now
    }

    let ip: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

    let key = BlockedIpKey { prefix_len: 32, addr_be: u32::from(ip.src_addr) };
    if unsafe { BLOCKED_IPS.get(&key) }.is_some() {
        return Ok(TC_ACT_SHOT);
    }

    let dest_port = extract_dest_port(ctx, &ip)?;
    if unsafe { ALLOWED_PORTS.get(&dest_port) }.is_some() {
        Ok(TC_ACT_OK)
    } else {
        Ok(TC_ACT_SHOT)
    }
}

fn extract_dest_port(ctx: &TcContext, ip: &Ipv4Hdr) -> Result<u16, ()> {
    // read TCP/UDP dest port at the right offset based on ip.ihl(); omitted here for brevity
    todo!()
}