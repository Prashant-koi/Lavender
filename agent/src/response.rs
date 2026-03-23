use crate::config::ResponseConfig;

pub enum ResponseAction {
    Kill { pid: u32, comm: String, score: u32 },
    Skipped { pid: u32, comm: String, reason: SkipReason },
}

pub enum SkipReason {
    DryRun,
    Protected,
    BelowThreshold,
    KillFailed,
}

pub struct ResponseEngine {
    dry_run: bool,
    kill_threshold: u32,
    protected: Vec<String>,
}

impl ResponseEngine {
    pub fn from_config(cfg: &ResponseConfig) -> Self {
        Self { dry_run: cfg.dry_run, kill_threshold: cfg.kill_threshold, protected: cfg.protected_comms.clone() }
    }

    // we will call the evaluate funtion whever a scored alert is fired and return "ResponseAction"
    pub fn evaluate(
        &self,
        pid: u32,
        comm: &str,
        score: u32,
    ) -> ResponseAction {
        // we will first if we have reached the kill threashold
        if score < self.kill_threshold {
            return  ResponseAction::Skipped {
                pid,
                comm: comm.to_string(),
                reason: SkipReason::BelowThreshold 
            };
        }

        // we also need to make sure we don't kill the comms in the protected list
        if self.protected.iter().any(|p| comm.contains(p.as_str())) {
            return  ResponseAction::Skipped {
                pid,
                comm: comm.to_string(),
                reason: SkipReason::Protected
            };
        }

        // if we are in a dry run then we will just log what we are supposed to do rather than 
        // actually do it
        if self.dry_run {
            return  ResponseAction::Skipped { 
                pid,
                comm: comm.to_string(),
                reason: SkipReason::DryRun
            };
        }

        // now finally actually kill the process after we have checked that
        let result = unsafe { libc::kill(pid as i32, libc::SIGKILL) };

        if result == 0 { // 0 means that it has been succefullly killed
            ResponseAction::Kill {
                pid,
                comm: comm.to_string(),
                score 
            }
        } else {
            // kill failed 
            ResponseAction::Skipped {
                pid,
                comm: comm.to_string(),
                reason: SkipReason::KillFailed
            }
        }
    }
}
