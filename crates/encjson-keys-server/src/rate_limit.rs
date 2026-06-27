use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub(crate) struct RateLimitCfg {
    pub(crate) per_minute: u64,
    pub(crate) requests_per_minute: u64,
}

#[derive(Default)]
pub(crate) struct RateLimiter {
    hits: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    pub(crate) fn check_and_record(&mut self, key: &str, limit: u64, window: Duration) -> bool {
        let now = Instant::now();
        let entries = self.hits.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        if entries.len() as u64 >= limit {
            return false;
        }
        entries.push(now);
        true
    }
}
