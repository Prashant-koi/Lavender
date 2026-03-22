use std::collections::HashMap;



#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARNING",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn from_score(score: u32) -> Self {
        match score {
            0..=49 => Severity::Info,
            50..=99 => Severity::Warning,
            100..=149 => Severity::High,
            _ => Severity::Critical,
        }
    }
}

// we will make a struct that will have the score entry for
// jus one proces
struct ProcessScore {
    score: u32,
    last_updated: u64,
    fired_rules: Vec<&'static str>, // we need to track riles so we don't double count the same rule that is firing repetedly
}

pub struct Scorer {
    scores:  HashMap<u32, ProcessScore>,
    decay_after: u64, // the score will decay as time passes to give more newer issues the priority
    decay_amount: u32, // how much score is subtracted per day
}

impl Scorer {
    pub fn new() -> Self {
        Self { 
            scores: HashMap::new(),
            decay_after: 60, // 60 seconds for no signals the decay starts
            decay_amount: 10, // 10 per decay tick
        }
    }

    // add_score function to add points to the score after a new rule/vunlerability hits
    // this will return the new severity after addition IF it corsses a certain threshold
    pub fn add_score(
        &mut self,
        pid: u32,
        rule: &'static str,
        points: u32,
    ) -> Option<(u32, Severity)> {
        let now = self.now_secs();
        let entry = self.scores.entry(pid).or_insert(ProcessScore { 
            score:  0,
            last_updated: now,
            fired_rules: vec![],
        });

        // we will aplly decay first if the decay_after benchmark time has passed
        let elapsed = now.saturating_sub(entry.last_updated);
        if elapsed > self.decay_after {
            let ticks = (elapsed / self.decay_after) as u32;
            entry.score = entry.score.saturating_sub(self.decay_amount * ticks);
        }

        // we will also not double count a rule/vulneribility firing repetedly on the same process
        if entry.fired_rules.contains(&rule) {
            return None;
        }

        entry.fired_rules.push(rule);
        entry.score += points;
        entry.last_updated = now;

        let severity = Severity::from_score(entry.score);

        // only return severity if the severity score is above the lable of "warning"
        if entry.score >= 50 {
            Some((entry.score, severity))
        } else {
            None
        }
    }
}