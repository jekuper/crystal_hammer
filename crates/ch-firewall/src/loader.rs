use aya::{
    maps::{Array, HashMap as AyaHashMap},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use aya::programs::tc::{NlOptions, TcAttachOptions};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Everything passes. This is the default.
    Regular = 0,
    /// Everything is denied except destination ports in the allow list.
    Lockdown = 1,
}

pub struct Firewall {
    bpf: Ebpf,
    iface: String,
}

impl Firewall {
    /// Loads the embedded eBPF bytecode and attaches it to `iface` at TC ingress.
    /// Starts in Regular mode.
    pub fn attach(iface: &str) -> anyhow::Result<Self> {
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ch-firewall-ebpf"));
        let mut bpf = Ebpf::load(bytes)?;

        let _ = tc::qdisc_add_clsact(iface); // idempotent; ignore "already exists"

        let prog: &mut SchedClassifier = bpf.program_mut("ch_firewall").unwrap().try_into()?;
        prog.load()?;
        prog.attach_with_options(
            iface,
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions {
                priority: 1, // low number = high priority = runs before other filters
                ..Default::default()
            }),
        )?;

        let mut fw = Self { bpf, iface: iface.to_string() };
        fw.set_mode(Mode::Regular)?; // explicit, though the map is zero-init'd anyway
        Ok(fw)
    }

    /// Switches between Regular (allow all) and Lockdown (deny all except
    /// the port allow list) modes.
    pub fn set_mode(&mut self, mode: Mode) -> anyhow::Result<()> {
        let mut map: Array<_, u32> = Array::try_from(self.bpf.map_mut("MODE").unwrap())?;
        map.set(0, mode as u32, 0)?;
        Ok(())
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

    /// IP blocking is currently disabled. Kept as a stub so callers/API
    /// consumers don't need to change when it's re-enabled.
    pub fn block_ip(&mut self, _addr: IpAddr, _prefix_len: u32) -> anyhow::Result<()> {
        anyhow::bail!("IP blocking is currently disabled")
    }

    pub fn unblock_ip(&mut self, _addr: IpAddr, _prefix_len: u32) -> anyhow::Result<()> {
        anyhow::bail!("IP blocking is currently disabled")
    }

    /// Detaches cleanly — dropping `bpf` unloads the program; interface goes back to normal.
    pub fn detach(self) -> anyhow::Result<()> {
        drop(self.bpf);
        Ok(())
    }
}