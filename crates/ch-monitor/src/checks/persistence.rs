//! Persistence-sweep checks (SPECS section 3 `persistence`).

use crate::{Cadence, Check, Finding};

/// authorized_keys created/modified anywhere (SPECS section 4).
pub struct AuthorizedKeys {
    _priv: (),
}

impl AuthorizedKeys {
    pub fn new() -> Self {
        AuthorizedKeys { _priv: () }
    }
}

impl Check for AuthorizedKeys {
    fn id(&self) -> ch_common::ImplId {
        "persistence.authorized_keys"
    }

    fn cadence(&self) -> Cadence {
        Cadence::Poll
    }

    fn run(&self, _host: &ch_sense::HostSnapshot) -> Vec<Finding> {
        // Enumerate every account's authorized_keys and report the key count per file, so
        // an operator can eyeball a rogue key. Read-only.
        let mut homes: Vec<String> = vec!["/root".to_string()];
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                if let Some(home) = line.split(':').nth(5) {
                    if home.starts_with('/') && home != "/" {
                        homes.push(home.trim_end_matches('/').to_string());
                    }
                }
            }
        }
        homes.sort();
        homes.dedup();

        let mut findings = Vec::new();
        for home in homes {
            let path = format!("{home}/.ssh/authorized_keys");
            let Ok(content) = std::fs::read_to_string(&path) else { continue };
            let keys: Vec<&str> = content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            if keys.is_empty() {
                continue;
            }
            // Report the key comment (last field) of each entry - that's the human-readable
            // label an operator scans for something they don't recognize.
            let labels: Vec<&str> = keys.iter().map(|k| k.split_whitespace().last().unwrap_or("")).collect();
            findings.push(Finding {
                check: self.id().to_string(),
                severity: crate::Severity::Info,
                summary: format!("{} authorized key(s) in {path}", keys.len()),
                detail: serde_json::json!({ "path": path, "count": keys.len(), "labels": labels }),
            });
        }
        findings
    }
}
