#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

use aya_ebpf::{
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
};

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

/// Operating modes for the firewall, stored in `MODE[0]`.
const MODE_REGULAR: u32 = 0; // default — everything passes
const MODE_LOCKDOWN: u32 = 1; // deny-by-default — only ALLOWED_PORTS gets through

/// Single-slot config map controlling the current mode. Defaults to 0
/// (Regular) since BPF array maps are zero-initialized.
#[map]
static MODE: Array<u32> = Array::with_max_entries(1, 0);

/// Destination ports allowed through in Lockdown mode. Shared by both
/// IPv4 and IPv6 traffic since ports are a transport-layer concept.
#[map]
static ALLOWED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(1024, 0);

// IP blocking is disabled for now. The map is left declared (unused) so the
// on-disk map layout doesn't churn if/when this gets re-enabled; nothing in
// try_filter() consults it.
//
// #[map]
// static BLOCKED_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[classifier]
pub fn ch_firewall(ctx: TcContext) -> i32 {
    match try_filter(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => TC_ACT_OK, // fail-open on parse errors — flip to TC_ACT_SHOT if you want fail-closed
    }
}

fn current_mode() -> u32 {
    unsafe { MODE.get(0) }.copied().unwrap_or(MODE_REGULAR)
}

fn try_filter(ctx: &TcContext) -> Result<i32, ()> {
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;

    // Only IPv4/IPv6 are subject to filtering; everything else (ARP, etc.)
    // passes through untouched in both modes.
    match eth.ether_type {
        EtherType::Ipv4 | EtherType::Ipv6 => {}
        _ => return Ok(TC_ACT_OK),
    }

    // Regular mode: allow everything, no need to even parse further.
    if current_mode() != MODE_LOCKDOWN {
        return Ok(TC_ACT_OK);
    }

    // --- Lockdown mode from here down ---

    let (l4_offset, proto) = match eth.ether_type {
        EtherType::Ipv4 => {
            let ip: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            let ihl_bytes = (ip.ihl() as usize) * 4;
            (EthHdr::LEN + ihl_bytes, ip.proto)
        }
        EtherType::Ipv6 => {
            // NOTE: this assumes no IPv6 extension headers between the fixed
            // header and the L4 header. Traffic using extension headers
            // (fragmentation, hop-by-hop options, etc.) will fail to parse
            // and fail-open per the classifier's error handling above.
            let ip: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            (EthHdr::LEN + Ipv6Hdr::LEN, ip.next_hdr)
        }
        _ => unreachable!(), // filtered above
    };

    match proto {
        IpProto::Tcp | IpProto::Udp => {}
        _ => return Ok(TC_ACT_SHOT), // lockdown: non-TCP/UDP is denied
    }

    let dest_port = extract_dest_port(ctx, l4_offset)?;
    if unsafe { ALLOWED_PORTS.get(&dest_port) }.is_some() {
        Ok(TC_ACT_OK)
    } else {
        Ok(TC_ACT_SHOT)
    }
}

/// TCP and UDP both place the destination port at bytes 2..4 of the L4
/// header, so one code path covers both protocols.
fn extract_dest_port(ctx: &TcContext, l4_offset: usize) -> Result<u16, ()> {
    let raw: u16 = ctx.load(l4_offset + 2).map_err(|_| ())?;
    Ok(u16::from_be(raw))
}