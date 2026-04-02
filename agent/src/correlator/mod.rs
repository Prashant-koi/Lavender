use std::collections::{HashMap, VecDeque};

use crate::config::Filters;
use crate::detection::path::basename;
use crate::output::format::now_secs;

mod rules;

// what kind of event we are going to buffer
#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    Exec,
    Connect,
    FileOpen,
}

// a single event will be stored in the buffer
#[derive(Debug, Clone)]
pub struct BufferedEvent {
    pub kind: EventKind,
    pub comm: String,
    pub detail: String, // this will be the filename for exec or open and ip:port for connect event kind
    pub timestamp: u64,
    pub ancestry: String,
}

impl BufferedEvent {
    pub fn exec(comm: String, filename: String, ancestry: String) -> Self {
        Self {
            kind: EventKind::Exec,
            comm,
            detail: filename,
            timestamp: now_secs(),
            ancestry,
        }
    }

    pub fn connect(comm: String, dest_ip: String, ancestry: String) -> Self {
        Self {
            kind: EventKind::Connect,
            comm,
            detail: dest_ip,
            timestamp: now_secs(),
            ancestry,
        }
    }

    pub fn file_open(comm: String, filename: String, ancestry: String) -> Self {
        Self {
            kind: EventKind::FileOpen,
            comm,
            detail: filename,
            timestamp: now_secs(),
            ancestry,
        }
    }
}


// use this when an alert is produced by correlation
pub struct CorrelationAlert {
    pub pid: u32,
    pub rule: &'static str,
    pub detail: String, // same as in the BufferedEvent struct
}

// this will be our main correlator strucr
pub struct Correlator {
    buffers: HashMap<u32, VecDeque<BufferedEvent>>,//pid to recent events mapping for a given pid
    max_events: usize, // the max events to keep per process
    max_age_secs: u64, // max age before an event is stale
    sensitive_file_patterns: Vec<String>,
    noisy_comms: Vec<String>,
}

impl Correlator { // implementing some methids for the correlator struct
    pub fn from_filters(filters: &Filters) -> Self {
        Self { 
            buffers: HashMap::new(),
            max_events: filters.correlator_max_events,
            max_age_secs: filters.correlator_max_age_secs,
            sensitive_file_patterns: filters.sensitive_files.clone(),
            noisy_comms: filters.noisy_comms.clone(),
        }
    }

    // we wil call this every time anu event arrives and push that to the buffers
    pub fn push(
        &mut self,
        pid: u32,
        event: BufferedEvent,
    ) -> Option<CorrelationAlert> {
        
        let now = now_secs();

        {
            let buf = self.buffers.entry(pid).or_insert_with(VecDeque::new);

            //we will evict events that are too old by checking with max_age_secs 
            // and we will check from the front since VecDeque is oldest-first
            while let Some(front) = buf.front() {
                let age = now.saturating_sub(front.timestamp);
                if age > self.max_age_secs {
                    buf.pop_front();
                } else {
                    break;
                }
            }

            // if we are at capacity we will evict the front since it will be the oldest
            if buf.len() >= self.max_events {
                buf.pop_front();
            }

            buf.push_back(event);
        } // mutable borrow ends here

        self.check_sequences(pid, now)
    }

    // we have to clean up the processes buffer when it exists
    pub fn remove(&mut self, pid: u32) {
        self.buffers.remove(&pid);
    }

    // we will deifne the sequence rule of processes and determine the seeverity and what the sequence might be doing
    // according to the rules
    // the rules themselves will be basic and will just send an alert and it will be the responsibility of the user to 
    // determine what to do with the problem and/or use our resolver that I will write later on
    fn check_sequences(
        &self,
        pid: u32,
        _now: u64,
    ) -> Option<CorrelationAlert> {
        let current_buf = self.buffers.get(&pid)?;
        let current_event = current_buf.back()?;

        let related_events = self.collect_related_events(pid, &current_event.ancestry, _now);
        if related_events.is_empty() {
            return None;
        }

        // checking for noisly false positives
        let latest_comm = current_buf.back().map(|e| e.comm.as_str()).unwrap_or("");
        if self.noisy_comms.iter().any(|s| latest_comm.contains(s.as_str())) {
            return None;
        }

        // Reverse shell behaviour rule.
        if let Some(alert) = rules::reverse_shell_rule(pid, &related_events) {
            return Some(alert);
        }

        // Rule checking for execution after sensitive file read.
        if let Some(alert) = rules::cred_exec_rule(self, pid, &related_events) {
            return Some(alert);
        }

        // Rule checking for rapid process spawning.
        rules::rapid_spawn_rule(self, pid, current_event, &related_events)
    }

    fn collect_related_events(
        &self,
        pid: u32,
        ancestry: &str,
        now: u64,
    ) -> Vec<BufferedEvent> {
        let mut events: Vec<BufferedEvent> = self
            .buffers
            .iter()
            .flat_map(|(event_pid, buf)| {
                buf.iter().filter_map(move |e| {
                    let same_pid = *event_pid == pid;
                    let related_ancestry = Self::is_related_ancestry(ancestry, &e.ancestry);
                    let fresh = now.saturating_sub(e.timestamp) <= self.max_age_secs;

                    if fresh && (same_pid || related_ancestry) {
                        Some(e.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        events.sort_by_key(|e| e.timestamp);
        events
    }

    pub(super) fn is_noisy_comm(&self, comm: &str) -> bool {
        self.noisy_comms
            .iter()
            .any(|s| comm.contains(s.as_str()))
    }

    pub(super) fn ancestry_has_noisy_comm(ancestry: &str, noisy_comms: &[String]) -> bool {
        ancestry
            .split("=>")
            .any(|segment| noisy_comms.iter().any(|n| segment.contains(n.as_str())))
    }

    fn is_related_ancestry(a: &str, b: &str) -> bool {
        if a.is_empty() || b.is_empty() || a == "unknown" || b == "unknown" {
            return false;
        }

        a == b || Self::is_prefix_chain(a, b) || Self::is_prefix_chain(b, a)
    }

    fn is_prefix_chain(prefix: &str, full: &str) -> bool {
        if full == prefix {
            return true;
        }

        let mut prefixed = String::with_capacity(prefix.len() + 2);
        prefixed.push_str(prefix);
        prefixed.push_str("=>");
        full.starts_with(&prefixed)
    }

    pub(super) fn is_exec_target(event: &BufferedEvent, target_shell: &str) -> bool {
        if event.kind != EventKind::Exec {
            return false;
        }

        let target_base = basename(&event.detail);
        target_base == target_shell
    }

    pub(super) fn is_external_connect(event: &BufferedEvent) -> bool {
        if event.kind != EventKind::Connect {
            return false;
        }

        !event.detail.starts_with("127.") && event.detail != "::1"
    }


}