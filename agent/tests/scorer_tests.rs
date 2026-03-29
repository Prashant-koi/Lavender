use agent::scorer::{ScoreContext, Scorer, Severity};

// Verifies rule scores accumulate and map to the expected severity band.
#[test]
fn scorer_adds_points_and_sets_severity() {
    let mut scorer = Scorer::new();

    // 40 + 35 gets us into warning threshold
    assert!(scorer.add_score_for_rule(100, "T1059 [Unexpected shell spawn]").is_none());
    let scored = scorer.add_score_for_rule(100, "T1003 [Sensitive file read]");

    assert!(scored.is_some());
    let (score, severity) = scored.unwrap();
    assert_eq!(score, 75);
    assert_eq!(severity, Severity::Warning);
}

// Ensures the same rule is not double-counted for the same process.
#[test]
fn scorer_dedups_same_rule_per_pid() {
    let mut scorer = Scorer::new();
    let ctx = ScoreContext {
        ancestry: "zsh=>bash",
        parent_comm: Some("zsh"),
        child_comm: Some("bash"),
        is_sequence_match: false,
    };

    // use a high-value rule so first call must cross threshold and return Some
    let first = scorer.add_score_for_rule_with_context(200, "CHAIN Reverse shell behaviour", &ctx);
    let second = scorer.add_score_for_rule_with_context(200, "CHAIN Reverse shell behaviour", &ctx);

    assert!(first.is_some());
    assert!(second.is_none());
}

// Confirms score breakdown reports base and context bonuses as expected.
#[test]
fn scorer_returns_context_breakdown_components() {
    let mut scorer = Scorer::new();
    let ctx = ScoreContext {
        ancestry: "code=>zsh=>bash",
        parent_comm: Some("zsh"),
        child_comm: Some("bash"),
        is_sequence_match: true,
    };

    let scored = scorer
        .add_score_for_rule_with_context(300, "CHAIN Reverse shell behaviour", &ctx)
        .expect("expected scored output");

    let (_score, _severity, breakdown) = scored;
    assert_eq!(breakdown.base, 90);
    assert_eq!(breakdown.lineage_bonus, 10);
    assert_eq!(breakdown.rarity_bonus, 25);
    assert_eq!(breakdown.sequence_bonus, 20);
}

// Verifies rarity bonus decreases after repeated parent-child pair observations.
#[test]
fn rare_parent_child_bonus_decays_with_repeats() {
    let mut scorer = Scorer::new();
    let ctx = ScoreContext {
        ancestry: "zsh=>bash",
        parent_comm: Some("zsh"),
        child_comm: Some("bash"),
        is_sequence_match: false,
    };

    let one = scorer
        .add_score_for_rule_with_context(1, "T1059 [Unexpected shell spawn]", &ctx)
        .expect("first score")
        .2
        .rarity_bonus;
    let two = scorer
        .add_score_for_rule_with_context(2, "T1059 [Unexpected shell spawn]", &ctx)
        .expect("second score")
        .2
        .rarity_bonus;
    let three = scorer
        .add_score_for_rule_with_context(3, "T1059 [Unexpected shell spawn]", &ctx)
        .expect("third score")
        .2
        .rarity_bonus;

    assert_eq!(one, 25);
    assert_eq!(two, 15);
    assert_eq!(three, 15);
}
