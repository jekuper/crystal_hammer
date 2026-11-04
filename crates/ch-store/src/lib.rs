//! Local state on redb: the runtime watchlist overrides and the append-only, hash-chained
//! evidence log (SPECS 13.8). The evidence log is tamper-evident: each record commits the
//! hash of the one before it, so a deletion or edit breaks the chain.

#![forbid(unsafe_code)]

pub mod evidence;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ch_common::{Error, Hash, Result};
use redb::{Database, ReadableTable, TableDefinition};

use evidence::Record;

/// Depth/file caps for the baseline walk, matching the live integrity rescan.
const BASELINE_MAX_DEPTH: usize = 8;
const BASELINE_MAX_FILES: usize = 20_000;

/// BLAKE3-hash every regular file under `paths` (recursively, capped). Follows a symlink
/// only when it is a top-level entry. Shared by the `baseline`/`diff` command and the
/// agent's auto-baseline so both hash identically.
pub fn hash_paths(paths: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for root in paths {
        let mut stack = vec![(PathBuf::from(root), 0usize)];
        while let Some((p, depth)) = stack.pop() {
            if out.len() >= BASELINE_MAX_FILES {
                return out;
            }
            let meta = if depth == 0 { std::fs::metadata(&p) } else { std::fs::symlink_metadata(&p) };
            let Ok(meta) = meta else { continue };
            if meta.is_dir() {
                if depth >= BASELINE_MAX_DEPTH {
                    continue;
                }
                if let Ok(entries) = std::fs::read_dir(&p) {
                    stack.extend(entries.flatten().map(|e| (e.path(), depth + 1)));
                }
            } else if meta.is_file() {
                if let Ok(bytes) = std::fs::read(&p) {
                    out.insert(p.display().to_string(), Hash::of(&bytes).to_string());
                }
            }
        }
    }
    out
}

// Evidence log, keyed by monotonic cursor; value is the JSON-encoded Record.
const EVIDENCE: TableDefinition<u64, &[u8]> = TableDefinition::new("evidence");
// Small key/value scratch: currently just the last record's chain hash.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
// Runtime watchlist edits, kept as add/remove sets so defaults can still evolve across
// versions while operator edits persist (a removed default is tombstoned).
const WL_ADD: TableDefinition<&str, u8> = TableDefinition::new("watchlist_add");
const WL_REMOVE: TableDefinition<&str, u8> = TableDefinition::new("watchlist_remove");
// T0 integrity baseline: watched-file path -> content hash (hex).
const BASELINE: TableDefinition<&str, &str> = TableDefinition::new("baseline");
// Operator acknowledgements: evidence cursor -> note. Kept out of the append-only log so
// the evidence chain stays tamper-evident; acking is triage metadata, not evidence.
const ACK: TableDefinition<u64, &str> = TableDefinition::new("alert_ack");
// Runtime edits to the suspicious-binary list, as add/remove sets over the compiled-in
// defaults (same scheme as the watchlist).
const SUSPECT_ADD: TableDefinition<&str, u8> = TableDefinition::new("suspect_add");
const SUSPECT_REMOVE: TableDefinition<&str, u8> = TableDefinition::new("suspect_remove");

const META_LAST_HASH: &str = "last_hash";

fn store_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Store(e.to_string())
}

fn to32(bytes: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    let n = bytes.len().min(32);
    a[..n].copy_from_slice(&bytes[..n]);
    a
}

/// Handle to the on-disk state. Wraps a single redb database file. Cheap to clone behind
/// an `Arc`; redb serializes writers itself, so no external lock is needed.
pub struct Store {
    db: Database,
}

impl Store {
    /// Open (or create) the state database under `state_dir`.
    pub fn open(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let db = Database::create(state_dir.join("state.redb")).map_err(store_err)?;
        // Materialize every table so later read txns never hit a missing table.
        let w = db.begin_write().map_err(store_err)?;
        {
            w.open_table(EVIDENCE).map_err(store_err)?;
            w.open_table(META).map_err(store_err)?;
            w.open_table(WL_ADD).map_err(store_err)?;
            w.open_table(WL_REMOVE).map_err(store_err)?;
            w.open_table(BASELINE).map_err(store_err)?;
            w.open_table(ACK).map_err(store_err)?;
            w.open_table(SUSPECT_ADD).map_err(store_err)?;
            w.open_table(SUSPECT_REMOVE).map_err(store_err)?;
        }
        w.commit().map_err(store_err)?;
        Ok(Store { db })
    }

    // ---- Evidence log ----------------------------------------------------

    /// Append one record, chaining it to the previous one, and return its cursor.
    pub fn append(&self, kind: &str, body: &serde_json::Value) -> Result<u64> {
        let w = self.db.begin_write().map_err(store_err)?;
        let cursor;
        {
            let mut ev = w.open_table(EVIDENCE).map_err(store_err)?;
            let mut meta = w.open_table(META).map_err(store_err)?;

            cursor = ev
                .last()
                .map_err(store_err)?
                .map(|(k, _)| k.value())
                .unwrap_or(0)
                + 1;
            let prev = meta
                .get(META_LAST_HASH)
                .map_err(store_err)?
                .map(|g| to32(g.value()))
                .unwrap_or([0u8; 32]);

            let rec = Record {
                cursor,
                prev,
                kind: kind.to_string(),
                body: body.clone(),
            };
            let bytes = serde_json::to_vec(&rec)?;
            let hash = rec.hash();

            ev.insert(cursor, bytes.as_slice()).map_err(store_err)?;
            meta.insert(META_LAST_HASH, &hash.0[..]).map_err(store_err)?;
        }
        w.commit().map_err(store_err)?;
        Ok(cursor)
    }

    /// Records with cursor strictly greater than `after`, up to `limit`, in order.
    pub fn since(&self, after: u64, limit: usize) -> Result<Vec<Record>> {
        let r = self.db.begin_read().map_err(store_err)?;
        let ev = r.open_table(EVIDENCE).map_err(store_err)?;
        let mut out = Vec::new();
        for item in ev.range(after.saturating_add(1)..).map_err(store_err)? {
            let (_, v) = item.map_err(store_err)?;
            out.push(serde_json::from_slice::<Record>(v.value())?);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Highest cursor written so far (0 if the log is empty).
    pub fn latest_cursor(&self) -> Result<u64> {
        let r = self.db.begin_read().map_err(store_err)?;
        let ev = r.open_table(EVIDENCE).map_err(store_err)?;
        let cursor = ev.last().map_err(store_err)?.map(|(k, _)| k.value()).unwrap_or(0);
        Ok(cursor)
    }

    /// Verify the whole evidence chain from genesis. Reads the entire log.
    pub fn verify(&self) -> Result<bool> {
        let r = self.db.begin_read().map_err(store_err)?;
        let ev = r.open_table(EVIDENCE).map_err(store_err)?;
        let mut records = Vec::new();
        for item in ev.iter().map_err(store_err)? {
            let (_, v) = item.map_err(store_err)?;
            records.push(serde_json::from_slice::<Record>(v.value())?);
        }
        Ok(evidence::verify_chain(&records))
    }

    // ---- Watchlist overrides --------------------------------------------

    /// Persist a runtime watchlist addition (clears any tombstone for it).
    pub fn add_watch(&self, path: &str) -> Result<()> {
        let w = self.db.begin_write().map_err(store_err)?;
        {
            w.open_table(WL_ADD).map_err(store_err)?.insert(path, 1).map_err(store_err)?;
            w.open_table(WL_REMOVE).map_err(store_err)?.remove(path).map_err(store_err)?;
        }
        w.commit().map_err(store_err)?;
        Ok(())
    }

    /// Persist a runtime watchlist removal (tombstones a default, drops a prior add).
    pub fn remove_watch(&self, path: &str) -> Result<()> {
        let w = self.db.begin_write().map_err(store_err)?;
        {
            w.open_table(WL_REMOVE).map_err(store_err)?.insert(path, 1).map_err(store_err)?;
            w.open_table(WL_ADD).map_err(store_err)?.remove(path).map_err(store_err)?;
        }
        w.commit().map_err(store_err)?;
        Ok(())
    }

    /// Apply the persisted add/remove sets to `base`, returning a sorted, deduped list.
    pub fn effective_watchlist(&self, base: Vec<String>) -> Result<Vec<String>> {
        let r = self.db.begin_read().map_err(store_err)?;
        let mut set: BTreeSet<String> = base.into_iter().collect();
        for item in r.open_table(WL_ADD).map_err(store_err)?.iter().map_err(store_err)? {
            let (k, _) = item.map_err(store_err)?;
            set.insert(k.value().to_string());
        }
        for item in r.open_table(WL_REMOVE).map_err(store_err)?.iter().map_err(store_err)? {
            let (k, _) = item.map_err(store_err)?;
            set.remove(k.value());
        }
        Ok(set.into_iter().collect())
    }

    // ---- Integrity baseline ---------------------------------------------

    /// Replace the baseline with `entries` (path -> content-hash hex).
    pub fn set_baseline(&self, entries: &[(String, String)]) -> Result<()> {
        let w = self.db.begin_write().map_err(store_err)?;
        w.delete_table(BASELINE).map_err(store_err)?;
        {
            let mut t = w.open_table(BASELINE).map_err(store_err)?;
            for (path, hash) in entries {
                t.insert(path.as_str(), hash.as_str()).map_err(store_err)?;
            }
        }
        w.commit().map_err(store_err)?;
        Ok(())
    }

    /// Hash the given paths now and store the result as the baseline. Returns the count.
    pub fn take_baseline(&self, paths: &[String]) -> Result<usize> {
        let entries: Vec<(String, String)> = hash_paths(paths).into_iter().collect();
        let n = entries.len();
        self.set_baseline(&entries)?;
        Ok(n)
    }

    /// Discard the stored baseline (flush).
    pub fn clear_baseline(&self) -> Result<()> {
        let w = self.db.begin_write().map_err(store_err)?;
        w.delete_table(BASELINE).map_err(store_err)?;
        {
            w.open_table(BASELINE).map_err(store_err)?;
        }
        w.commit().map_err(store_err)?;
        Ok(())
    }

    /// The stored baseline as (path, hash) pairs; empty if none was taken.
    pub fn baseline(&self) -> Result<Vec<(String, String)>> {
        let r = self.db.begin_read().map_err(store_err)?;
        let t = r.open_table(BASELINE).map_err(store_err)?;
        let mut out = Vec::new();
        for item in t.iter().map_err(store_err)? {
            let (k, v) = item.map_err(store_err)?;
            out.push((k.value().to_string(), v.value().to_string()));
        }
        Ok(out)
    }

    // ---- Alert acknowledgements -----------------------------------------

    /// Mark the alert at `cursor` acknowledged, with an optional note.
    pub fn ack_alert(&self, cursor: u64, note: &str) -> Result<()> {
        let w = self.db.begin_write().map_err(store_err)?;
        {
            w.open_table(ACK).map_err(store_err)?.insert(cursor, note).map_err(store_err)?;
        }
        w.commit().map_err(store_err)?;
        Ok(())
    }

    /// Clear the acknowledgement on the alert at `cursor`.
    pub fn unack_alert(&self, cursor: u64) -> Result<()> {
        let w = self.db.begin_write().map_err(store_err)?;
        {
            w.open_table(ACK).map_err(store_err)?.remove(cursor).map_err(store_err)?;
        }
        w.commit().map_err(store_err)?;
        Ok(())
    }

    /// Set of acknowledged alert cursors.
    pub fn acked_cursors(&self) -> Result<BTreeSet<u64>> {
        let r = self.db.begin_read().map_err(store_err)?;
        let t = r.open_table(ACK).map_err(store_err)?;
        let mut out = BTreeSet::new();
        for item in t.iter().map_err(store_err)? {
            let (k, _) = item.map_err(store_err)?;
            out.insert(k.value());
        }
        Ok(out)
    }

    /// Wipe the whole evidence log and reset the hash chain to genesis, and drop all
    /// acknowledgements. An explicit operator "flush" - the log holds only alerts.
    pub fn clear_alerts(&self) -> Result<()> {
        let w = self.db.begin_write().map_err(store_err)?;
        w.delete_table(EVIDENCE).map_err(store_err)?;
        w.delete_table(ACK).map_err(store_err)?;
        {
            w.open_table(EVIDENCE).map_err(store_err)?;
            w.open_table(ACK).map_err(store_err)?;
            w.open_table(META).map_err(store_err)?.remove(META_LAST_HASH).map_err(store_err)?;
        }
        w.commit().map_err(store_err)?;
        Ok(())
    }

    // ---- Suspicious-binary overrides ------------------------------------

    /// Persist a runtime addition to the suspicious-binary list.
    pub fn add_suspect(&self, name: &str) -> Result<()> {
        let w = self.db.begin_write().map_err(store_err)?;
        {
            w.open_table(SUSPECT_ADD).map_err(store_err)?.insert(name, 1).map_err(store_err)?;
            w.open_table(SUSPECT_REMOVE).map_err(store_err)?.remove(name).map_err(store_err)?;
        }
        w.commit().map_err(store_err)?;
        Ok(())
    }

    /// Persist a runtime removal (tombstones a default, drops a prior add).
    pub fn remove_suspect(&self, name: &str) -> Result<()> {
        let w = self.db.begin_write().map_err(store_err)?;
        {
            w.open_table(SUSPECT_REMOVE).map_err(store_err)?.insert(name, 1).map_err(store_err)?;
            w.open_table(SUSPECT_ADD).map_err(store_err)?.remove(name).map_err(store_err)?;
        }
        w.commit().map_err(store_err)?;
        Ok(())
    }

    /// Apply the persisted add/remove sets to `base`, returning a sorted, deduped list.
    pub fn effective_suspects(&self, base: Vec<String>) -> Result<Vec<String>> {
        let r = self.db.begin_read().map_err(store_err)?;
        let mut set: BTreeSet<String> = base.into_iter().collect();
        for item in r.open_table(SUSPECT_ADD).map_err(store_err)?.iter().map_err(store_err)? {
            let (k, _) = item.map_err(store_err)?;
            set.insert(k.value().to_string());
        }
        for item in r.open_table(SUSPECT_REMOVE).map_err(store_err)?.iter().map_err(store_err)? {
            let (k, _) = item.map_err(store_err)?;
            set.remove(k.value());
        }
        Ok(set.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ch-store-test-{}-{}", std::process::id(), rand_tag()))
    }

    fn rand_tag() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[test]
    fn evidence_chains_and_verifies() {
        let dir = tmp();
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.latest_cursor().unwrap(), 0);

        let c1 = s.append("alert", &serde_json::json!({"n": 1})).unwrap();
        let c2 = s.append("alert", &serde_json::json!({"n": 2})).unwrap();
        assert_eq!((c1, c2), (1, 2));
        assert_eq!(s.latest_cursor().unwrap(), 2);

        let recs = s.since(0, 10).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].prev, [0u8; 32], "genesis prev is zero");
        assert_eq!(recs[1].prev, recs[0].hash().0, "chain links");
        assert!(s.verify().unwrap());

        // Catch-up after a cursor returns only newer records.
        assert_eq!(s.since(1, 10).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn watchlist_overrides_apply() {
        let dir = tmp();
        let s = Store::open(&dir).unwrap();
        s.add_watch("/tmp/extra").unwrap();
        s.remove_watch("/etc/passwd").unwrap();

        let eff = s
            .effective_watchlist(vec!["/etc/passwd".into(), "/etc/ssh".into()])
            .unwrap();
        assert!(eff.contains(&"/tmp/extra".to_string()));
        assert!(eff.contains(&"/etc/ssh".to_string()));
        assert!(!eff.contains(&"/etc/passwd".to_string()), "tombstoned default dropped");

        // Re-adding clears the tombstone.
        s.add_watch("/etc/passwd").unwrap();
        let eff = s.effective_watchlist(vec!["/etc/passwd".into()]).unwrap();
        assert!(eff.contains(&"/etc/passwd".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn baseline_round_trips_and_replaces() {
        let dir = tmp();
        let s = Store::open(&dir).unwrap();
        assert!(s.baseline().unwrap().is_empty());

        s.set_baseline(&[("/a".into(), "h1".into()), ("/b".into(), "h2".into())]).unwrap();
        let mut got = s.baseline().unwrap();
        got.sort();
        assert_eq!(got, vec![("/a".to_string(), "h1".to_string()), ("/b".to_string(), "h2".to_string())]);

        // set_baseline replaces wholesale.
        s.set_baseline(&[("/c".into(), "h3".into())]).unwrap();
        assert_eq!(s.baseline().unwrap(), vec![("/c".to_string(), "h3".to_string())]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
