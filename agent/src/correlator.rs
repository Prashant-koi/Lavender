use std::{collections::{HashMap, VecDeque}, time::{SystemTime, UNIX_EPOCH}};

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
    pub  severity: u32, // this is the severity score the caller will decide what to do with it
}

// this will be our main correlator strucr
pub struct Correlator {
    buffers: HashMap<u32, VecDeque<BufferedEvent>>,//pid to recent events mapping for a given pid
    max_events: usize, // the max events to keep per process
    max_age_secs: u64, // max age before an event is stale
}

impl Correlator { // implementing some methids for the correlator struct
    pub fn new() -> Self {
        Self { 
            buffers: HashMap::new(),
            max_events: 20, 
            max_age_secs: 30,
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
                if now - front.timestamp > self.max_age_secs {
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

        // we wil first collect the event kinds in order which will just make the overall process easier for us
        let kinds: Vec<&EventKind> = related_events.iter().map(|e| &e.kind).collect();

        // Reverse shell behaviour rule
        // this will check for the pattern when bash was spawned and it made a network connection
        let has_shell_exec = related_events.iter().any(|e| 
            e.kind == EventKind::Exec &&
            ["bash","sh","zsh","dash","fish"].iter().any(|s| e.comm.contains(s))
        );

        let has_external_connect = related_events.iter().any(|e|
            e.kind == EventKind::Connect &&
            !e.detail.starts_with("127.")
        );

        if has_shell_exec && has_external_connect {
            return Some(CorrelationAlert { 
                pid,
                rule: "CHAIN Reverse shell behaviour",
                detail: format!(
                    "process {} executed a shell AND made external connection within 30 seconds",
                    related_events.last().map(|e| e.comm.as_str()).unwrap_or("unknown")
                ),
                severity: 90, // if this happens there is a high chance it is malicious
            });
        }

        // rule chekcing for execution after file read
        // we will try to find the patter of openign a sensitive file and then executing something
        let read_sensitive = related_events.iter().any(|e|
            e.kind == EventKind::FileOpen &&
            ["/etc/shadow", "/etc/passwd","id_rsa"].iter()
                .any(|s| e.detail.contains(s))
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
                severity: 75,
            });
        }

        // rule checking for rapid process spawning for things like fork bomb, worm, enumeration scripts
        // the pattern it will check for is more than 5 exec events in 10s seconds, I feel like this will
        // have alot of false positives
        let exec_count = related_events.iter().filter(|e| e.kind == EventKind::Exec).count();

        if exec_count >= 5 {
            let oldest_exec = related_events.iter().filter(|e| e.kind == EventKind::Exec).next().map(|e| e.timestamp).unwrap_or(0);

            let newest_exec = related_events.iter().filter(|e| e.kind == EventKind::Exec).last().map(|e| e.timestamp).unwrap_or(0);

            // all 5 or more withing 10 secs
            if newest_exec - oldest_exec < 10 {
                return Some(CorrelationAlert { 
                    pid,
                    rule: "CHAIN Rapid process spawning",
                    detail: format!(
                        "{} processes spawned within 10 seconds",
                        exec_count
                    ),
                    severity: 60,
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


}