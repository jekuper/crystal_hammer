//! Agent configuration (TOML on disk, SPECS 13.12).
//!
//! `state_dir` is a configurable path (default below), created if it does not exist.


pub const CH_PORT: u16 = 2222;


use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Where redb state and the evidence log live. Created if missing.
    pub state_dir: PathBuf,
    /// Port the SPA-gated listener binds once knocked open.
    pub listen_port: u16,
    /// File paths/globs to watch for modification (SPECS 4a). Merged with built-in
    /// defaults at load time.
    pub watchlist: Vec<String>,
    /// Allow taking over the audit daemon slot if no daemon is running
    pub allow_audit_daemon: bool,
}

/// Files and directories worth tracking on a typical box before any operator
/// customization. Missing paths are skipped by the engine, so this can be broad. More can
/// be added at runtime via `watch add`; per-user SSH key dirs are added by the agent.
///
/// Covers the common blue-team service stack (Linux only): directories are watched because
/// the integrity rescan walks them recursively.
pub fn default_watchlist() -> Vec<String> {
    [
        // Identity, auth, privilege
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/pam.d",
        "/etc/login.defs",
        "/etc/security",
        "/etc/ssh",
        "/etc/krb5.conf",
        "/etc/krb5.keytab",
        // Scheduled execution and boot/persistence surfaces
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/etc/systemd/system",
        "/etc/rc.local",
        "/etc/profile",
        "/etc/profile.d",
        "/etc/bash.bashrc",
        "/etc/ld.so.preload",
        "/etc/modules",
        "/etc/modules-load.d",
        "/etc/modprobe.d",
        // System / network basics
        "/etc/hosts",
        "/etc/hostname",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/fstab",
        // Package sources (Debian/Ubuntu, RHEL/Rocky, Alpine, SUSE)
        "/etc/apt/sources.list",
        "/etc/apt/sources.list.d",
        "/etc/yum.repos.d",
        "/etc/apk/repositories",
        "/etc/zypp/repos.d",
        // Centralized logging / Graylog
        "/etc/rsyslog.conf",
        "/etc/rsyslog.d",
        "/etc/syslog-ng",
        "/etc/graylog",
        // Certificate authority / TLS material
        "/etc/pki",
        "/etc/ssl",
        "/etc/letsencrypt",
        "/etc/step",
        "/etc/easy-rsa",
        // Containers / orchestration (Docker, containerd, Kubernetes, CNI)
        "/etc/docker",
        "/etc/containerd",
        "/etc/crio",
        "/etc/kubernetes",
        "/etc/cni/net.d",
        // Config management
        "/etc/ansible",
        // Databases (MySQL/MariaDB, PostgreSQL)
        "/etc/my.cnf",
        "/etc/my.cnf.d",
        "/etc/mysql",
        "/etc/postgresql",
        // Web / proxy servers and app frontends
        "/etc/nginx",
        "/etc/apache2",
        "/etc/httpd",
        "/etc/haproxy",
        "/etc/traefik",
        // Web content roots - attackers deface/backdoor the served files, not just config.
        // The integrity rescan walks these recursively (capped); narrow with watch if huge.
        "/var/www",
        "/usr/share/nginx/html",
        "/srv/www",
        "/srv/http",
        // Access / runtime security
        "/etc/teleport.yaml",
        "/etc/falco",
        // Observability
        "/etc/prometheus",
        "/etc/alertmanager",
        "/etc/grafana",
        "/etc/influxdb",
        "/etc/influxdb2",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Binaries whose execution is treated as a critical alert (by basename). These are
/// download/exfil tools, interpreters, recon, persistence, defense-evasion, package
/// managers, compilers and container-escape helpers - things that rarely run unprompted
/// on a locked-down production host mid-incident. Operators extend/trim this at runtime
/// with `suspect add|remove`. Deliberately excludes core shells/coreutils (sh, bash, ls,
/// cat, ...) which would self-flood.
pub fn default_suspicious_bins() -> Vec<String> {
    [
        // Download / transfer / reverse-shell
        "curl", "wget", "nc", "ncat", "netcat", "socat", "tftp", "ftp", "lftp", "scp",
        "sftp", "rsync", "telnet",
        // Interpreters (common payload / reverse-shell hosts)
        "python", "python3", "perl", "ruby", "php", "lua", "awk", "gawk",
        // Recon / discovery
        "whoami", "hostname", "w", "who", "last", "lastlog", "netstat", "arp", "nmap",
        "ping", "dig", "nslookup", "host", "lsof", "finger",
        // Account / persistence changes
        "useradd", "userdel", "usermod", "passwd", "chpasswd", "groupadd", "visudo",
        "crontab", "at", "insmod", "modprobe", "chattr", "update-rc.d",
        // Defense evasion / anti-forensics
        "auditctl", "setenforce", "iptables", "nft", "ufw", "shred", "wipe", "truncate",
        "journalctl", "logrotate", "dmesg",
        // Package managers
        "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "pip", "pip3", "npm", "gem", "snap",
        // Compilers
        "gcc", "cc", "clang", "make", "ld",
        // Container / namespace escape
        "docker", "kubectl", "crictl", "runc", "ctr", "nsenter", "unshare", "chroot", "capsh",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            state_dir: PathBuf::from("/var/lib/crystal_hammer"),
            listen_port: 0,
            watchlist: default_watchlist(),
            allow_audit_daemon: false,
        }
    }
}
