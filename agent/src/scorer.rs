use std::collections::HashMap;

use crate::output::format;


// point values for each detection rule
pub const SCORE_SHELL_SPAWN:        u32 = 40;  // T1059 unexpected shell spawn
pub const SCORE_SENSITIVE_FILE:     u32 = 35;  // T1003 sensitive file read
pub const SCORE_SUSPICIOUS_PORT:    u32 = 45;  // T1071 known C2 port
pub const SCORE_SHELL_NETWORK:      u32 = 60;  // shell making outbound connection
pub const SCORE_FIRST_NET_CALLER:   u32 = 15;  // first time network caller
pub const SCORE_CHAIN_REVERSE_SHELL: u32 = 90; // correlation: shell + network
pub const SCORE_CHAIN_CRED_EXEC:    u32 = 75;  // correlation: cred read + exec
pub const SCORE_CHAIN_RAPID_SPAWN:  u32 = 60;  // correlation: rapid spawning
pub const SCORE_OBFUSCATED_CMD:     u32 = 55;  // T1027 obfuscated command execution

// Single source of truth for rule which does the points mapping.
// Keep the rule labels exactly aligned with detection/correlation rule strings.
pub fn score_for_rule(rule: &str) -> Option<u32> {
    match rule {
        "T1059 [Unexpected shell spawn]" => Some(SCORE_SHELL_SPAWN),
        "T1003 [Sensitive file read]" => Some(SCORE_SENSITIVE_FILE),
        "T1071 [Connection to suspicious port]" => Some(SCORE_SUSPICIOUS_PORT),
        "T1059 [Shell making outbound connection]" => Some(SCORE_SHELL_NETWORK),
        "T1071 [First time Network Caller]" => Some(SCORE_FIRST_NET_CALLER),
        "T1027 [Obfuscated command execution]" => Some(SCORE_OBFUSCATED_CMD),
        "CHAIN Reverse shell behaviour" => Some(SCORE_CHAIN_REVERSE_SHELL),
        "CHAIN Credential access then execution" => Some(SCORE_CHAIN_CRED_EXEC),
        "CHAIN Rapid process spawning" => Some(SCORE_CHAIN_RAPID_SPAWN),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy)]
pub struct ScoreBreakdown {
    pub base: u32,
    pub lineage_bonus: u32,
    pub rarity_bonus: u32,
    pub sequence_bonus: u32,
}

pub struct ScoreContext<'a> {
    pub ancestry: &'a str,
    pub parent_comm: Option<&'a str>,
    pub child_comm: Option<&'a str>,
    pub is_sequence_match: bool,
}

impl<'a> Default for ScoreContext<'a> {
    fn default() -> Self {
        Self {
            ancestry: "",
            parent_comm: None,
            child_comm: None,
            is_sequence_match: false,
        }
    }
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
    parent_child_seen: HashMap<(String, String), u32>,
    decay_after: u64, // the score will decay as time passes to give more newer issues the priority
    decay_amount: u32, // how much score is subtracted per day
}

impl Scorer {
    pub fn new() -> Self {
        Self { 
            scores: HashMap::new(),
            parent_child_seen: HashMap::new(),
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
        let now = format::now_secs();
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

    // Use this for normal runtime scoring so callsites only pass the rule label.
    pub fn add_score_for_rule(
        &mut self,
        pid: u32,
        rule: &'static str,
    ) -> Option<(u32, Severity)> {
        let ctx = ScoreContext::default();
        self.add_score_for_rule_with_context(pid, rule, &ctx)
            .map(|(score, severity, _)| (score, severity))
    }

    // use this when you want extra context-aware points in addition to base rule points
    pub fn add_score_for_rule_with_context(
        &mut self,
        pid: u32,
        rule: &'static str,
        ctx: &ScoreContext,
    ) -> Option<(u32, Severity, ScoreBreakdown)> {
        let base = score_for_rule(rule)?;

        // we will keep this de-dup behaviour so we don't re-add the same rule per pid
        if let Some(existing) = self.scores.get(&pid) {
            if existing.fired_rules.contains(&rule) {
                return None;
            }
        }

        // lineage points are derived from depth of ancestry chain
        let lineage_bonus = Self::lineage_bonus(ctx.ancestry);

        // rare parent-child pair will give more points on first few sightings
        let rarity_bonus = self.rare_parent_child_bonus(ctx.parent_comm, ctx.child_comm);

        // sequence rules are high confidence so we can bias scores towrds them a bit more
        let sequence_bonus = if ctx.is_sequence_match { 20 } else { 0 };

        let total_points = base
            .saturating_add(lineage_bonus)
            .saturating_add(rarity_bonus)
            .saturating_add(sequence_bonus);

        let (score, severity) = self.add_score(pid, rule, total_points)?;

        Some((
            score,
            severity,
            ScoreBreakdown {
                base,
                lineage_bonus,
                rarity_bonus,
                sequence_bonus,
            },
        ))
    }

    pub fn remove(&mut self, pid: u32) { // clean up the score when a process exits
        self.scores.remove(&pid);
    }

    pub fn get_score(&self, pid: u32) -> u32 {
        self.scores.get(&pid).map(|e| e.score).unwrap_or(0)
    }

    fn lineage_bonus(ancestry: &str) -> u32 {
        if ancestry.is_empty() || ancestry == "unknown" {
            return 0;
        }

        // this is just a simple depth-based bonus with cap so it does not overpower the actual base rule socer points
        let depth = ancestry
            .split("=>")
            .filter(|s| !s.is_empty())
            .count() as u32;

        let useful_hops = depth.saturating_sub(1);
        useful_hops.saturating_mul(5).min(20)
    }

    // if there is a rare parent to child ancestry then it will add a bonus to the scores
    // as this might be a new form of attack
    fn rare_parent_child_bonus(
        &mut self,
        parent_comm: Option<&str>,
        child_comm: Option<&str>,
    ) -> u32 {
        let parent = match parent_comm {
            Some(v) if !v.is_empty() => v,
            _ => return 0,
        };

        let child = match child_comm {
            Some(v) if !v.is_empty() => v,
            _ => return 0,
        };

        let key = (parent.to_string(), child.to_string());
        let seen = self.parent_child_seen.get(&key).copied().unwrap_or(0);

        // this is the novelty bonus the one which is first seen gets the biggest lift
        let bonus = match seen {
            0 => 25,
            1..=2 => 15,
            3..=5 => 8,
            _ => 0,
        };

        self.parent_child_seen.insert(key, seen + 1);
        bonus
    }
}