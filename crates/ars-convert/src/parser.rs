use anyhow::Result;
use ars_format::{Rule, RuleAction, RuleType};
use tracing::warn;

// ── AdGuardHome / uBlock Origin parser ───────────────────────────────────────
//
// Supported syntax:
//   ||example.com^          → block suffix (matches example.com and *.example.com)
//   ||example.com^$important→ block suffix (ignore $important modifier for now)
//   @@||example.com^        → allow suffix (whitelist)
//   /regex/                 → block regex
//   @@/regex/               → allow regex
//   127.0.0.1 example.com   → hosts-style block exact
//   0.0.0.0 example.com     → hosts-style block exact
//   example.com             → block exact (plain domain line)
//   ! comment               → ignored
//   # comment               → ignored

pub fn parse_adguard(content: &str) -> Vec<Rule> {
    let mut rules = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }

        if let Some(rule) = parse_adguard_line(line) {
            rules.push(rule);
        }
    }

    rules
}

fn parse_adguard_line(line: &str) -> Option<Rule> {
    // Whitelist: @@||domain^ or @@/regex/
    if let Some(rest) = line.strip_prefix("@@") {
        return parse_adguard_pattern(rest, RuleAction::Allow);
    }

    // Hosts file: "127.0.0.1 domain" or "0.0.0.0 domain"
    if line.starts_with("127.0.0.1 ")
        || line.starts_with("0.0.0.0 ")
        || line.starts_with("::1 ")
        || line.starts_with(":: ")
    {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() == 2 {
            let domain = parts[1].split_whitespace().next()?;
            if is_valid_domain(domain) && domain != "localhost" {
                return Some(Rule::block_exact(domain));
            }
        }
        return None;
    }

    parse_adguard_pattern(line, RuleAction::Block)
}

fn parse_adguard_pattern(pattern: &str, action: RuleAction) -> Option<Rule> {
    // Regex rule: /pattern/
    if pattern.starts_with('/') && pattern.ends_with('/') && pattern.len() > 2 {
        let regex_str = &pattern[1..pattern.len() - 1];
        return Some(Rule {
            action,
            rule_type: RuleType::Regex,
            pattern: regex_str.to_string(),
            source: None,
        });
    }

    // Domain rule: ||domain^  or  ||domain^$modifiers
    if let Some(rest) = pattern.strip_prefix("||") {
        // Strip trailing ^ and modifiers
        let domain = rest
            .split('^')
            .next()?
            .split('$')
            .next()?
            .trim_end_matches('.')
            .trim();

        if domain.is_empty() {
            return None;
        }

        // Wildcard prefix like ||*.example.com^ → suffix rule for example.com
        let domain = domain.trim_start_matches("*.");
        if !is_valid_domain_or_wildcard(domain) {
            return None;
        }

        return Some(Rule {
            action,
            rule_type: RuleType::DomainSuffix,
            pattern: domain.to_lowercase(),
            source: None,
        });
    }

    // Plain domain (no || prefix) — treat as exact
    let domain = pattern.split('$').next()?.trim().trim_end_matches('.');
    if is_valid_domain(domain) {
        return Some(Rule {
            action,
            rule_type: RuleType::DomainExact,
            pattern: domain.to_lowercase(),
            source: None,
        });
    }

    None
}

// ── Mihomo (Clash-Meta) YAML parser ──────────────────────────────────────────
//
// Expected format:
//   payload:
//     - DOMAIN,example.com
//     - DOMAIN-SUFFIX,example.com
//     - DOMAIN-KEYWORD,keyword
//     - DOMAIN-REGEX,pattern
//     - +.example.com          ← shorthand for DOMAIN-SUFFIX
//     - example.com            ← plain domain (exact)

pub fn parse_mihomo(content: &str) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    let mut in_payload = false;

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line == "payload:" || line.starts_with("payload:") {
            in_payload = true;
            continue;
        }

        if in_payload {
            // YAML list item starting with "- "
            if let Some(item) = line.strip_prefix("- ") {
                // Strip optional quotes
                let item = item.trim_matches('"').trim_matches('\'');

                if let Some(rule) = parse_mihomo_item(item) {
                    rules.push(rule);
                }
            } else if !line.starts_with(' ') && !line.starts_with('\t') {
                // New top-level key → end of payload
                in_payload = false;
            }
        }
    }

    Ok(rules)
}

fn parse_mihomo_item(item: &str) -> Option<Rule> {
    // DOMAIN-SUFFIX,example.com or +.example.com
    if let Some(rest) = item.strip_prefix("+.") {
        if is_valid_domain(rest) {
            return Some(Rule::block_suffix(rest));
        }
        return None;
    }

    // Typed rules: TYPE,value
    if let Some((type_str, value)) = item.split_once(',') {
        let value = value.trim();
        return match type_str.trim().to_uppercase().as_str() {
            "DOMAIN" => {
                if is_valid_domain(value) {
                    Some(Rule::block_exact(value))
                } else {
                    None
                }
            }
            "DOMAIN-SUFFIX" => {
                if is_valid_domain(value) {
                    Some(Rule::block_suffix(value))
                } else {
                    None
                }
            }
            "DOMAIN-KEYWORD" => Some(Rule {
                action: RuleAction::Block,
                rule_type: RuleType::DomainKeyword,
                pattern: value.to_lowercase(),
                source: None,
            }),
            "DOMAIN-REGEX" => Some(Rule {
                action: RuleAction::Block,
                rule_type: RuleType::Regex,
                pattern: value.to_string(),
                source: None,
            }),
            // IP-CIDR rules: reserved for future
            "IP-CIDR" | "IP-CIDR6" => None,
            other => {
                warn!("Unknown Mihomo rule type: {}", other);
                None
            }
        };
    }

    // Plain domain
    if is_valid_domain(item) {
        return Some(Rule::block_exact(item));
    }

    None
}

// ── Plain domain list ─────────────────────────────────────────────────────────
//
// One domain per line, # comments, blank lines ignored.
// Leading *. means suffix match, otherwise exact.

pub fn parse_domain_list(content: &str) -> Vec<Rule> {
    let mut rules = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Strip inline comments
        let line = line.split('#').next().unwrap_or("").trim();

        if let Some(domain) = line.strip_prefix("*.") {
            if is_valid_domain(domain) {
                rules.push(Rule::block_suffix(domain));
            }
        } else if is_valid_domain(line) {
            rules.push(Rule::block_exact(line));
        }
    }

    rules
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn is_valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    // Must contain at least one dot (except single-label like "localhost")
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.starts_with('.')
        && !s.ends_with('.')
}

fn is_valid_domain_or_wildcard(s: &str) -> bool {
    // Allow leading *. already stripped by caller
    is_valid_domain(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adguard_block_suffix() {
        let rules = parse_adguard("||example.com^\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, "example.com");
        assert_eq!(rules[0].rule_type, RuleType::DomainSuffix);
    }

    #[test]
    fn test_adguard_allow() {
        let rules = parse_adguard("@@||safe.com^\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, RuleAction::Allow);
    }

    #[test]
    fn test_adguard_regex() {
        let rules = parse_adguard("/ads\\./\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_type, RuleType::Regex);
    }

    #[test]
    fn test_adguard_hosts() {
        let rules = parse_adguard("0.0.0.0 tracker.com\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_type, RuleType::DomainExact);
    }

    #[test]
    fn test_mihomo_suffix() {
        let rules = parse_mihomo("payload:\n  - +.example.com\n").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_type, RuleType::DomainSuffix);
    }

    #[test]
    fn test_mihomo_typed() {
        let rules = parse_mihomo(
            "payload:\n  - DOMAIN-KEYWORD,ads\n  - DOMAIN,exact.com\n",
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].rule_type, RuleType::DomainKeyword);
        assert_eq!(rules[1].rule_type, RuleType::DomainExact);
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    // ── AdGuard tests ────────────────────────────────────────────────────────

    #[test]
    fn test_adguard_comment_skipped() {
        let rules = parse_adguard("! This is a comment\n# Also a comment\n||ads.com^\n");
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_adguard_modifiers_stripped() {
        // $important and other modifiers should be ignored
        let rules = parse_adguard("||example.com^$important\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, "example.com");
    }

    #[test]
    fn test_adguard_wildcard_prefix() {
        // ||*.example.com^ → suffix rule for example.com
        let rules = parse_adguard("||*.example.com^\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_type, RuleType::DomainSuffix);
        assert_eq!(rules[0].pattern, "example.com");
    }

    #[test]
    fn test_adguard_hosts_zero() {
        let rules = parse_adguard("0.0.0.0 ads.tracker.com\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_type, RuleType::DomainExact);
        assert_eq!(rules[0].action, RuleAction::Block);
    }

    #[test]
    fn test_adguard_regex_allow() {
        let rules = parse_adguard("@@/safe\\.cdn\\./\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_type, RuleType::Regex);
        assert_eq!(rules[0].action, RuleAction::Allow);
    }

    // ── Mihomo tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_mihomo_empty_payload() {
        let rules = parse_mihomo("payload:\n").unwrap();
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_mihomo_quoted_entries() {
        let rules = parse_mihomo(
            "payload:\n  - \"DOMAIN,example.com\"\n  - '+.ads.io'\n"
        ).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].rule_type, RuleType::DomainExact);
        assert_eq!(rules[1].rule_type, RuleType::DomainSuffix);
    }

    #[test]
    fn test_mihomo_keyword() {
        let rules = parse_mihomo(
            "payload:\n  - DOMAIN-KEYWORD,doubleclick\n"
        ).unwrap();
        assert_eq!(rules[0].rule_type, RuleType::DomainKeyword);
        assert_eq!(rules[0].pattern, "doubleclick");
    }

    #[test]
    fn test_mihomo_ip_cidr_skipped() {
        // IP-CIDR rules should be silently skipped (not supported yet)
        let rules = parse_mihomo(
            "payload:\n  - IP-CIDR,1.2.3.0/24\n  - DOMAIN,example.com\n"
        ).unwrap();
        assert_eq!(rules.len(), 1);
    }

    // ── Domain list tests ────────────────────────────────────────────────────

    #[test]
    fn test_domain_list_inline_comment() {
        let rules = parse_domain_list("ads.com # advertising\ntrack.net\n");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].pattern, "ads.com");
    }

    #[test]
    fn test_domain_list_wildcard() {
        let rules = parse_domain_list("*.ads.com\ntrack.net\n");
        assert_eq!(rules[0].rule_type, RuleType::DomainSuffix);
        assert_eq!(rules[0].pattern, "ads.com");
        assert_eq!(rules[1].rule_type, RuleType::DomainExact);
    }
}
