// ch-firewall/src/loader.rs

use aya::{
    maps::{Array, HashMap as AyaHashMap},
    programs::{tc, SchedClassifier, TcAttachType},
};
use aya::programs::tc::{NlOptions, TcAttachOptions, SchedClassifierLinkId};
use aya::Ebpf;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::link::LinkAttribute;
use rtnetlink::constants::RTMGRP_LINK;
use rtnetlink::sys::{AsyncSocket, SocketAddr};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use std::sync::OnceLock;
use futures::{StreamExt, TryStreamExt};
use netlink_packet_route::link::LinkFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Everything passes. This is the default.
    Regular = 0,
    /// Everything is denied except destination ports in the allow list.
    Lockdown = 1,
}

/// Bookkeeping for one attached interface.
struct AttachedIface {
    name: String,
    link_id: SchedClassifierLinkId,
}

struct Inner {
    bpf: Ebpf,
    /// ifindex -> attachment state. Keyed by ifindex (stable across renames),
    /// not name.
    attached: HashMap<u32, AttachedIface>,
}

pub struct Firewall {
    inner: Mutex<Inner>,
    shutdown: Notify,
}

/// Why `run()` (and therefore `spawn_supervised()`) stopped.
#[derive(thiserror::Error, Debug)]
pub enum FirewallRunError {
    #[error("firewall run loop failed: {0:#}")]
    Run(#[source] anyhow::Error),

    #[error(
        "firewall run loop failed ({run_err:#}), and cleanup also failed \
         (some interfaces may still be attached): {detach_err:#}"
    )]
    RunAndCleanupFailed {
        run_err: anyhow::Error,
        detach_err: anyhow::Error,
    },

    #[error(
        "firewall shut down, but detach failed (some interfaces may still \
         be attached): {0:#}"
    )]
    DetachFailed(#[source] anyhow::Error),
}



static FIREWALL: OnceLock<Arc<Firewall>> = OnceLock::new();

impl Firewall {
    /// Loads the firewall and installs it as the process-wide singleton.
    /// Must be called exactly once, before `global()` is used anywhere.
    /// Typically called near the top of `main`.
    pub fn init_global() -> anyhow::Result<Arc<Firewall>> {
        let fw = Arc::new(Firewall::load()?);
        FIREWALL
            .set(fw.clone())
            .map_err(|_| anyhow::anyhow!("Firewall::init_global called more than once"))?;
        Ok(fw)
    }

    /// Accesses the process-wide firewall instance from anywhere — no need
    /// to thread it through function signatures or trait objects.
    ///
    /// Panics if `init_global()` hasn't been called yet. This is
    /// intentional: any command reaching for the firewall before it's
    /// loaded is a startup-ordering bug, not a recoverable runtime state,
    /// so failing loudly and immediately beats returning `Option` and
    /// pushing the "what if it's None" question onto every call site.
    pub fn global() -> Arc<Firewall> {
        FIREWALL
            .get()
            .expect("Firewall::global() called before Firewall::init_global()")
            .clone()
    }

    /// Loads the embedded eBPF bytecode and loads the program into the
    /// kernel, but does NOT attach it to any interface yet. Call `run()`
    /// (or `spawn_supervised()`) to start attaching to interfaces and
    /// watching for changes.
    pub fn load() -> anyhow::Result<Self> {
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ch-firewall-ebpf"));
        let mut bpf = Ebpf::load(bytes)?;

        let prog: &mut SchedClassifier = bpf.program_mut("ch_firewall").unwrap().try_into()?;
        prog.load()?;

        let fw = Self {
            inner: Mutex::new(Inner { bpf, attached: HashMap::new() }),
            shutdown: Notify::new(),
        };
        fw.set_mode_sync(Mode::Regular)?; // explicit, though the map is zero-init'd anyway
        Ok(fw)
    }

    // --- mode / allow-list controls ---

    pub async fn set_mode(&self, mode: Mode) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        set_mode_on(&mut inner.bpf, mode)
    }

    fn set_mode_sync(&self, mode: Mode) -> anyhow::Result<()> {
        let mut inner = self.inner.try_lock().expect("no concurrent access during load()");
        set_mode_on(&mut inner.bpf, mode)
    }

    pub async fn allow_port(&self, port: u16) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        let mut map: AyaHashMap<_, u16, u8> =
            AyaHashMap::try_from(inner.bpf.map_mut("ALLOWED_PORTS").unwrap())?;
        map.insert(port, 1, 0)?;
        Ok(())
    }

    pub async fn remove_allow_port(&self, port: u16) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        let mut map: AyaHashMap<_, u16, u8> =
            AyaHashMap::try_from(inner.bpf.map_mut("ALLOWED_PORTS").unwrap())?;
        map.remove(&port)?;
        Ok(())
    }

    pub async fn block_ip(&self, _addr: IpAddr, _prefix_len: u32) -> anyhow::Result<()> {
        anyhow::bail!("IP blocking is currently disabled")
    }

    pub async fn unblock_ip(&self, _addr: IpAddr, _prefix_len: u32) -> anyhow::Result<()> {
        anyhow::bail!("IP blocking is currently disabled")
    }

    // --- interface lifecycle ---

    /// Runs for the lifetime of the app: attaches to every non-loopback
    /// interface that exists now, then watches netlink for interfaces being
    /// added, removed, or renamed and keeps attachments in sync.
    ///
    /// Blocks until `shutdown()` is called, at which point it detaches from
    /// every interface and returns `Ok(())`. Any unrecoverable error
    /// (netlink socket failure, attach failure, etc.) stops the loop
    /// immediately; cleanup is still attempted before returning `Err`.
    ///
    /// Most callers want `spawn_supervised()` instead of calling this
    /// directly — it handles logging and background execution for you.
    pub async fn run(&self) -> Result<(), FirewallRunError> {
        let (mut conn, handle, mut messages) = rtnetlink::new_connection()
            .map_err(|e| FirewallRunError::Run(e.into()))?;

        // Join the RTMGRP_LINK multicast group so `messages` also yields
        // link add/remove/change notifications, not just our own requests.
        conn.socket_mut()
            .socket_mut()
            .bind(&SocketAddr::new(0, RTMGRP_LINK))
            .map_err(|e| FirewallRunError::Run(e.into()))?;

        let conn_task = tokio::spawn(conn);

        let run_result = self.run_inner(&handle, &mut messages).await;

        conn_task.abort();

        // Always try to detach whatever we have, whether we're exiting
        // cleanly via shutdown or bailing out on error, so we don't leave
        // stray TC filters behind.
        let detach_result = self.detach_all().await;

        match (run_result, detach_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(run_err), Ok(())) => Err(FirewallRunError::Run(run_err)),
            (Ok(()), Err(detach_err)) => Err(FirewallRunError::DetachFailed(detach_err)),
            (Err(run_err), Err(detach_err)) => {
                Err(FirewallRunError::RunAndCleanupFailed { run_err, detach_err })
            }
        }
    }

    async fn run_inner(
        &self,
        handle: &rtnetlink::Handle,
        messages: &mut (impl futures::Stream <
            Item = (
                NetlinkMessage<netlink_packet_route::RouteNetlinkMessage>,
                SocketAddr,
            ),
        > + Unpin),
    ) -> anyhow::Result<()> {
        // Initial sync: attach everything that already exists.
        let mut links = handle.link().get().execute();
        while let Some(msg) = links.try_next().await? {
            self.handle_link_message(msg).await?;
        }

        // Steady state: react to changes until shutdown is requested.
        loop {
            tokio::select! {
                biased;

                _ = self.shutdown.notified() => {
                    return Ok(());
                }

                next = messages.next() => {
                    match next {
                        Some((msg, _addr)) => {
                            self.handle_netlink_payload(msg).await?;
                        }
                        None => {
                            anyhow::bail!("netlink socket closed unexpectedly");
                        }
                    }
                }
            }
        }
    }

    /// Signals `run()` to detach from all interfaces and return. Safe to
    /// call from a different task than the one running `run()`.
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// Spawns `run()` on a background task and supervises it: logs the
    /// outcome (clean shutdown, fatal error, or panic) and then stops.
    /// It does NOT restart on crash — a failure is terminal for this
    /// task, by design, since a firewall silently restarting after an
    /// unknown failure is a worse failure mode than staying down and
    /// being loud about it.
    ///
    /// The returned `JoinHandle` can be used by the caller to `.await` for
    /// completion, or `.abort()` for an immediate stop. Prefer calling
    /// `shutdown()` before `.abort()`-ing though: `shutdown()` lets `run()`
    /// detach from every interface before it exits, while `.abort()` cancels
    /// the task at its next await point and may skip that cleanup, leaving
    /// TC filters attached on live interfaces.
    pub fn spawn_supervised(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            match self.run().await {
                Ok(()) => {
                    tracing::info!("firewall: shut down cleanly, detached from all interfaces");
                }
                Err(e @ FirewallRunError::Run(_)) => {
                    tracing::error!("firewall: run loop failed fatally, stopping (no restart): {e}");
                }
                Err(e @ FirewallRunError::RunAndCleanupFailed { .. }) => {
                    tracing::error!(
                        "firewall: run loop failed fatally AND cleanup failed, stopping (no restart): {e}"
                    );
                }
                Err(e @ FirewallRunError::DetachFailed(_)) => {
                    tracing::error!(
                        "firewall: shutdown was requested but cleanup failed: {e}"
                    );
                }
            }
        })
    }

    async fn handle_netlink_payload(
        &self,
        msg: NetlinkMessage<netlink_packet_route::RouteNetlinkMessage>,
    ) -> anyhow::Result<()> {
        use netlink_packet_route::RouteNetlinkMessage;

        match msg.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
                self.handle_link_message(link).await
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)) => {
                self.detach_iface(link.header.index).await
            }
            _ => Ok(()),
        }
    }

    /// Handles a NewLink message: attaches if it's a new, non-loopback
    /// interface; updates our bookkeeping if it's a rename of one we
    /// already track. Renames don't require re-attaching — TC filters are
    /// tied to the ifindex in the kernel, not the name.
    async fn handle_link_message(
        &self,
        link: netlink_packet_route::link::LinkMessage,
    ) -> anyhow::Result<()> {
        let ifindex = link.header.index;
        let is_loopback = link.header.flags.contains(LinkFlags::Loopback);

        let name = link.attributes.iter().find_map(|attr| {
            if let LinkAttribute::IfName(name) = attr {
                Some(name.clone())
            } else {
                None
            }
        });
        let Some(name) = name else { return Ok(()) };

        let mut inner = self.inner.lock().await;

        if let Some(existing) = inner.attached.get_mut(&ifindex) {
            if existing.name != name {
                tracing::info!(
                    "firewall: interface {ifindex} renamed {} -> {name}, attachment unaffected",
                    existing.name
                );
                existing.name = name;
            }
            return Ok(());
        }

        if is_loopback {
            return Ok(());
        }

        tracing::info!("firewall: attaching to new interface {name} (ifindex {ifindex})");
        attach_one(&mut inner, ifindex, &name)
    }

    async fn detach_iface(&self, ifindex: u32) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        if inner.attached.contains_key(&ifindex) {
            tracing::info!("firewall: interface {ifindex} removed, detaching");
        }
        detach_one(&mut inner, ifindex)
    }

    async fn detach_all(&self) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().await;
        let ifindexes: Vec<u32> = inner.attached.keys().copied().collect();
        let mut first_err = None;
        for ifindex in ifindexes {
            if let Err(e) = detach_one(&mut inner, ifindex) {
                tracing::warn!("firewall: failed to detach ifindex {ifindex}: {e:#}");
                first_err.get_or_insert(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn set_mode_on(bpf: &mut Ebpf, mode: Mode) -> anyhow::Result<()> {
    let mut map: Array<_, u32> = Array::try_from(bpf.map_mut("MODE").unwrap())?;
    map.set(0, mode as u32, 0)?;
    Ok(())
}

fn attach_one(inner: &mut Inner, ifindex: u32, name: &str) -> anyhow::Result<()> {
    let _ = tc::qdisc_add_clsact(name); // idempotent; ignore "already exists"

    let prog: &mut SchedClassifier = inner.bpf.program_mut("ch_firewall").unwrap().try_into()?;
    let link_id = prog.attach_with_options(
        name,
        TcAttachType::Ingress,
        TcAttachOptions::Netlink(NlOptions {
            priority: 1,
            ..Default::default()
        }),
    )?;

    inner.attached.insert(
        ifindex,
        AttachedIface { name: name.to_string(), link_id },
    );
    Ok(())
}

fn detach_one(inner: &mut Inner, ifindex: u32) -> anyhow::Result<()> {
    let Some(iface) = inner.attached.remove(&ifindex) else {
        return Ok(()); // not tracked — nothing to do
    };

    let prog: &mut SchedClassifier = inner.bpf.program_mut("ch_firewall").unwrap().try_into()?;
    // If the interface is already gone (DelLink race), the kernel will
    // already have torn down the filter along with it — treat "not found"
    // as success rather than a fatal error.
    match prog.detach(iface.link_id) {
        Ok(()) => Ok(()),
        Err(e) => {
            let e = anyhow::Error::from(e);
            if is_enodev(&e) { Ok(()) } else { Err(e) }
        }
    }
}

fn is_enodev(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|src| src.downcast_ref::<std::io::Error>())
        .any(|io_err| io_err.raw_os_error() == Some(libc::ENODEV))
}