use std::{collections::{HashMap, VecDeque}, time::{SystemTime, UNIX_EPOCH}};

use crate::config::Filters;

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

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
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
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

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

        // we wil first collect the event kinds in order which will just make the overall process easier for us
        let kinds: Vec<&EventKind> = related_events.iter().map(|e| &e.kind).collect();

        // Reverse shell behaviour rule
        // strict order: execve(bash) -> connect(external) -> execve(sh)
        // this is stronger than just checking shell + network happened sometime in the buffer
        for i in 0..related_events.len() {
            let first = &related_events[i];
            if !Self::is_exec_target(first, "bash") {
                continue;
            }

            for j in (i + 1)..related_events.len() {
                let second = &related_events[j];
                if !Self::is_external_connect(second) {
                    continue;
                }

                for k in (j + 1)..related_events.len() {
                    let third = &related_events[k];
                    if !Self::is_exec_target(third, "sh") {
                        continue;
                    }

                    return Some(CorrelationAlert {
                        pid,
                        rule: "CHAIN Reverse shell behaviour",
                        detail: format!(
                            "ordered reverse-shell chain matched: execve(bash) -> connect(external) -> execve(sh)"
                        ),
                    });
                }
            }
        }

        // rule chekcing for execution after file read
        // we will try to find the patter of openign a sensitive file and then executing something
        let read_sensitive = related_events.iter().any(|e|
            e.kind == EventKind::FileOpen &&
            self.sensitive_file_patterns
                .iter()
                .any(|s| e.detail.contains(s.as_str()))
        );

        let exec_after = kinds.windows(2).any(|w|
            w[0] == &EventKind::FileOpen &&
            w[1] == &EventKind::Exec
        );

        if read_sensitive && exec_after {
            return Some(CorrelationAlert { 
                pid,
                rule: "CHAIN Credential access then execution",
                detail: format!(
                    "process read sensitive file then executed a new process"
                ),
            });
        }

        // rule checking for rapid process spawning for things like fork bomb, worm, enumeration scripts
        // the pattern it will check for is more than 5 exec events in 10s seconds, I feel like this will
        // have alot of false positives
        // only evaluate this rule when the current event itself is exec so we don't keep re-firing on open/connect events
        if current_event.kind != EventKind::Exec {
            return None;
        }

        // exclude noisy comms from the rapid-spawn calculation to avoid editor/tooling burst false positives
        let exec_events: Vec<&BufferedEvent> = related_events
            .iter()
            .filter(|e| e.kind == EventKind::Exec)
            .filter(|e| !self.is_noisy_comm(&e.comm))
            .collect();

        // if the current chain ancestry is noisy (e.g. code), skip this rapid rule entirely
        if Self::ancestry_has_noisy_comm(&current_event.ancestry, &self.noisy_comms) {
            return None;
        }

        let exec_count = exec_events.len();

        if exec_count >= 5 {
            let oldest_exec = exec_events.first().map(|e| e.timestamp).unwrap_or(0);

            let newest_exec = exec_events.last().map(|e| e.timestamp).unwrap_or(0);

            // all 5 or more withing 10 secs
            if newest_exec - oldest_exec < 10 {
                return Some(CorrelationAlert { 
                    pid,
                    rule: "CHAIN Rapid process spawning",
                    detail: format!(
                        "{} processes spawned within 10 seconds",
                        exec_count
                    ),
                });
            }
        }

        None
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

    fn is_noisy_comm(&self, comm: &str) -> bool {
        self.noisy_comms
            .iter()
            .any(|s| comm.contains(s.as_str()))
    }

    fn ancestry_has_noisy_comm(ancestry: &str, noisy_comms: &[String]) -> bool {
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

    fn is_exec_target(event: &BufferedEvent, target_shell: &str) -> bool {
        if event.kind != EventKind::Exec {
            return false;
        }

        let target_base = basename(&event.detail);
        target_base == target_shell
    }

    fn is_external_connect(event: &BufferedEvent) -> bool {
        if event.kind != EventKind::Connect {
            return false;
        }

        !event.detail.starts_with("127.") && event.detail != "::1"
    }


}