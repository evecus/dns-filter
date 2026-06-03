use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use ars_format::{ArsReader, Rule, RuleAction, RuleType};
use parking_lot::RwLock;
use tracing::{info, warn};

use crate::matcher::{match_domain, MatchResult};

pub struct RuleEngine {
    /// Active compiled ruleset (from .ars files)
    ruleset: ArcSwap<Option<Arc<ArsReader>>>,
    /// Configured .ars file paths
    paths: RwLock<Vec<PathBuf>>,
    /// In-memory custom rules (added via API)
    custom_rules: RwLock<Vec<Rule>>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            ruleset: ArcSwap::new(Arc::new(None)),
            paths: RwLock::new(Vec::new()),
            custom_rules: RwLock::new(Vec::new()),
        }
    }

    pub fn load_files(&self, paths: &[PathBuf]) -> Result<()> {
        let mut loaded: Option<Arc<ArsReader>> = None;
        for path in paths {
            match ArsReader::from_file(path) {
                Ok(reader) => {
                    let c = &reader.metadata.rule_counts;
                    info!(
                        path = %path.display(),
                        block = c.block_exact + c.block_suffix + c.block_keyword + c.block_regex,
                        allow = c.allow_exact + c.allow_suffix,
                        "Loaded ruleset"
                    );
                    loaded = Some(Arc::new(reader));
                    break; // TODO: multi-file merge in v2
                }
                Err(e) => warn!(path=%path.display(), "Failed to load: {}", e),
            }
        }
        self.ruleset.store(Arc::new(loaded));
        *self.paths.write() = paths.to_vec();
        Ok(())
    }

    pub fn reload(&self) -> Result<()> {
        let paths = self.paths.read().clone();
        info!("Reloading {} ruleset(s)", paths.len());
        self.load_files(&paths)
    }

    pub fn query(&self, fqdn: &str) -> MatchResult {
        // Custom rules checked first (user overrides)
        let custom = self.custom_rules.read();
        if !custom.is_empty() {
            if let Some(r) = check_custom(&custom, fqdn) {
                return r;
            }
        }
        drop(custom);

        let guard = self.ruleset.load();
        match guard.as_ref() {
            Some(reader) => match_domain(reader, fqdn),
            None => MatchResult::NoMatch,
        }
    }

    pub fn metadata(&self) -> Option<ars_format::builder::ArsMetadata> {
        let guard = self.ruleset.load();
        guard.as_deref().map(|r| r.metadata.clone())
    }

    // ── Custom rule management ─────────────────────────────────────────────

    /// Parse a rule string in AdGuardHome syntax and add it.
    /// Examples: "||example.com^", "@@||safe.com^", "example.com"
    pub fn add_custom_rule(&self, s: &str) -> Result<()> {
        let rule = parse_custom_rule(s)?;
        let mut rules = self.custom_rules.write();
        // Dedup
        if !rules.iter().any(|r| r.pattern == rule.pattern && r.action == rule.action && r.rule_type == rule.rule_type) {
            rules.push(rule);
        }
        Ok(())
    }

    pub fn remove_custom_rule(&self, s: &str) -> Result<()> {
        let rule = parse_custom_rule(s)?;
        let mut rules = self.custom_rules.write();
        rules.retain(|r| !(r.pattern == rule.pattern && r.rule_type == rule.rule_type && r.action == rule.action));
        Ok(())
    }

    pub fn get_custom_rules(&self) -> Vec<String> {
        self.custom_rules.read().iter().map(rule_to_string).collect()
    }
}

impl Default for RuleEngine {
    fn default() -> Self { Self::new() }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn check_custom(rules: &[Rule], fqdn: &str) -> Option<MatchResult> {
    let domain = fqdn.trim_end_matches('.').to_lowercase();
    for rule in rules {
        let hit = match &rule.rule_type {
            RuleType::DomainExact   => domain == rule.pattern,
            RuleType::DomainSuffix  => domain == rule.pattern
                                    || domain.ends_with(&format!(".{}", rule.pattern)),
            RuleType::DomainKeyword => domain.contains(&rule.pattern),
            RuleType::Regex => {
                regex::Regex::new(&rule.pattern)
                    .map(|re| re.is_match(&domain))
                    .unwrap_or(false)
            }
            _ => false,
        };
        if hit {
            return Some(match &rule.action {
                RuleAction::Block          => MatchResult::Block,
                RuleAction::Allow          => MatchResult::Allow,
                RuleAction::Rewrite{target}=> MatchResult::Rewrite(target.clone()),
            });
        }
    }
    None
}

fn parse_custom_rule(s: &str) -> Result<Rule> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("@@||") {
        let domain = rest.split('^').next().unwrap_or("").trim_end_matches('.');
        return Ok(Rule::allow_suffix(domain));
    }
    if let Some(rest) = s.strip_prefix("||") {
        let domain = rest.split('^').next().unwrap_or("").trim_end_matches('.');
        return Ok(Rule::block_suffix(domain));
    }
    if s.starts_with('/') && s.ends_with('/') && s.len() > 2 {
        return Ok(Rule {
            action: RuleAction::Block,
            rule_type: RuleType::Regex,
            pattern: s[1..s.len()-1].to_string(),
            source: Some("custom".into()),
        });
    }
    // Plain domain
    Ok(Rule::block_exact(s))
}

fn rule_to_string(r: &Rule) -> String {
    match (&r.action, &r.rule_type) {
        (RuleAction::Allow, RuleType::DomainSuffix)  => format!("@@||{}^", r.pattern),
        (RuleAction::Allow, RuleType::DomainExact)   => format!("@@{}", r.pattern),
        (RuleAction::Block, RuleType::DomainSuffix)  => format!("||{}^", r.pattern),
        (RuleAction::Block, RuleType::DomainKeyword) => format!("||{}^$keyword", r.pattern),
        (RuleAction::Block, RuleType::Regex)         => format!("/{}/", r.pattern),
        _ => r.pattern.clone(),
    }
}
