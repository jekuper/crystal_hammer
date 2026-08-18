// ch-firewall-ebpf/src/main.rs
#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

use aya_ebpf::{
    macros::{classifier, map},
    maps::{HashMap, LpmTrie},
    programs::TcContext,
};
use network_types::{eth::{EthHdr, EtherType}, ip::Ipv4Hdr};

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;


use aya_ebpf::maps::lpm_trie::Key;

#[map]
static ALLOWED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static BLOCKED_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[classifier]
pub fn ch_firewall(ctx: TcContext) -> i32 {
    match try_filter(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => TC_ACT_OK, // fail-open on parse errors — flip to TC_ACT_SHOT if you want fail-closed
    }
}

fn try_filter(ctx: &TcContext) -> Result<i32, ()> {
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    let ether_type = eth.ether_type;
    if ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }

    let ip: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let src_addr = ip.src_addr;

    let key = Key::new(32, u32::from(src_addr));
    if BLOCKED_IPS.get(&key).is_some() {
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