use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    pub ts: DateTime<Utc>,
    pub client: String,
    pub domain: String,
    pub qtype: String,
    pub action: QueryAction,
    pub upstream: Option<String>,
    pub latency_ms: u64,
    pub cached: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryAction { Allow, Block, Rewrite, Cache }

#[derive(Debug, Serialize)]
pub struct LogStats {
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
    pub allowed: u64,
}

pub struct QueryLog {
    entries: Mutex<VecDeque<QueryLogEntry>>,
    max_size: usize,
    pub total:   AtomicU64,
    pub blocked: AtomicU64,
    pub cached:  AtomicU64,
    pub allowed: AtomicU64,
}

impl QueryLog {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(max_size)),
            max_size,
            total:   AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            cached:  AtomicU64::new(0),
            allowed: AtomicU64::new(0),
        }
    }

    pub fn push(&self, e: QueryLogEntry) {
        self.total.fetch_add(1, Ordering::Relaxed);
        match e.action {
            QueryAction::Block  => { self.blocked.fetch_add(1, Ordering::Relaxed); }
            QueryAction::Cache  => { self.cached.fetch_add(1, Ordering::Relaxed); }
            QueryAction::Allow  => { self.allowed.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
        let mut q = self.entries.lock().unwrap();
        if q.len() >= self.max_size { q.pop_front(); }
        q.push_back(e);
    }

    pub fn recent(&self, n: usize, filter: Option<&str>) -> Vec<QueryLogEntry> {
        let q = self.entries.lock().unwrap();
        q.iter().rev()
            .filter(|e| match filter {
                None    => true,
                Some(f) => e.domain.contains(f),
            })
            .take(n)
            .cloned()
            .collect()
    }

    pub fn stats(&self) -> LogStats {
        LogStats {
            total:   self.total.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            cached:  self.cached.load(Ordering::Relaxed),
            allowed: self.allowed.load(Ordering::Relaxed),
        }
    }
}
