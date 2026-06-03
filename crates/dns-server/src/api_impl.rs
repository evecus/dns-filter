use std::path::PathBuf;
use anyhow::Result;
use rule_engine::MatchResult;
use serde_json::Value;
use web_api::AppStateApi;
use crate::AppState;

impl AppStateApi for AppState {
    fn query_recent(&self, n: usize, filter: Option<&str>) -> Vec<Value> {
        self.log.recent(n, filter).into_iter()
            .map(|e| serde_json::to_value(e).unwrap_or_default())
            .collect()
    }

    fn query_stats(&self) -> Value {
        serde_json::to_value(self.log.stats()).unwrap_or_default()
    }

    fn engine_metadata(&self) -> Option<Value> {
        self.engine.metadata()
            .map(|m| serde_json::to_value(m).unwrap_or_default())
    }

    fn cache_len(&self) -> usize { self.cache.len() }

    fn test_domain(&self, domain: &str) -> String {
        match self.engine.query(domain) {
            MatchResult::Block       => "block".into(),
            MatchResult::Allow       => "allow".into(),
            MatchResult::Rewrite(t)  => format!("rewrite:{}", t),
            MatchResult::NoMatch     => "pass".into(),
        }
    }

    fn reload_rules(&self) -> Result<()> { self.engine.reload() }

    fn get_config(&self) -> Value {
        serde_json::to_value(self.config.read().clone()).unwrap_or_default()
    }

    fn update_config(&self, v: Value) -> Result<()> {
        let cfg: crate::config::Config = serde_json::from_value(v)?;
        *self.config.write() = cfg;
        Ok(())
    }

    fn get_rulesets(&self) -> Vec<Value> {
        self.config.read().rulesets.iter()
            .map(|r| serde_json::to_value(r).unwrap_or_default())
            .collect()
    }

    fn toggle_ruleset(&self, name: &str, enabled: bool) -> Result<()> {
        {
            let mut cfg = self.config.write();
            for rs in &mut cfg.rulesets {
                if rs.name == name { rs.enabled = enabled; }
            }
        }
        let paths: Vec<PathBuf> = self.config.read().rulesets.iter()
            .filter(|r| r.enabled)
            .map(|r| r.path.clone())
            .collect();
        self.engine.load_files(&paths)
    }

    fn add_custom_rule(&self, rule: &str) -> Result<()> {
        self.engine.add_custom_rule(rule)
    }

    fn remove_custom_rule(&self, rule: &str) -> Result<()> {
        self.engine.remove_custom_rule(rule)
    }

    fn get_custom_rules(&self) -> Vec<String> {
        self.engine.get_custom_rules()
    }
}
