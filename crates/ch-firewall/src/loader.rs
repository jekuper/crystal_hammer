use aya::{
    maps::{HashMap as AyaHashMap, lpm_trie::{LpmTrie, Key}},
    programs::{SchedClassifier, TcAttachType, tc},
    Ebpf,
};
use ch_firewall_common::BlockedIpKey;
use std::net::Ipv4Addr;

pub struct Firewall {
    bpf: Ebpf,
    iface: String,
}

impl Firewall {
    /// Loads the embedded eBPF bytecode and attaches it to `iface` at TC ingress.
    pub fn attach(iface: &str) -> anyhow::Result<Self> {
        // The bytecode built by build.rs, baked directly into this binary.
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ch-firewall-ebpf"));
        let mut bpf = Ebpf::load(bytes)?;

        let _ = tc::qdisc_add_clsact(iface); // idempotent; ignore "already exists"

        let prog: &mut SchedClassifier = bpf.program_mut("ch_firewall").unwrap().try_into()?;
        prog.load()?;
        prog.attach(iface, TcAttachType::Ingress)?;

        Ok(Self { bpf, iface: iface.to_string() })
    }

    pub fn allow_port(&mut self, port: u16) -> anyhow::Result<()> {
        let mut map: AyaHashMap<_, u16, u8> =
            AyaHashMap::try_from(self.bpf.map_mut("ALLOWED_PORTS").unwrap())?;
        map.insert(port, 1, 0)?;
        Ok(())
    }

    pub fn deny_port(&mut self, port: u16) -> anyhow::Result<()> {
        let mut map: AyaHashMap<_, u16, u8> =
            AyaHashMap::try_from(self.bpf.map_mut("ALLOWED_PORTS").unwrap())?;
        map.remove(&port)?;
        Ok(())
    }

    pub fn block_ip(&mut self, addr: Ipv4Addr, prefix_len: u32) -> anyhow::Result<()> {
        let mut map: LpmTrie<_, BlockedIpKey, u8> =
            LpmTrie::try_from(self.bpf.map_mut("BLOCKED_IPS").unwrap())?;
        let key = Key::new(prefix_len, BlockedIpKey { prefix_len, addr_be: u32::from(addr).to_be() });
        map.insert(&key, 1, 0)?;
        Ok(())
    }

    /// Detaches cleanly — dropping `bpf` unloads the program; interface goes back to normal.
    pub fn detach(self) -> anyhow::Result<()> {
        drop(self.bpf);
        Ok(())
    }
}