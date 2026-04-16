use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubbedEnvironment {
    pub kept: Vec<(String, String)>,
    pub removed: Vec<String>,
}

pub fn scrub_current_environment(
    scrub_patterns: &[String],
    passthrough_patterns: &[String],
) -> ScrubbedEnvironment {
    scrub_environment(std::env::vars(), scrub_patterns, passthrough_patterns)
}

pub fn scrub_environment<I>(
    vars: I,
    scrub_patterns: &[String],
    passthrough_patterns: &[String],
) -> ScrubbedEnvironment
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut kept = Vec::new();
    let mut removed = BTreeSet::new();

    for (name, value) in vars {
        let passes_passthrough = matches_any_pattern(&name, passthrough_patterns);
        let should_scrub = matches_any_pattern(&name, scrub_patterns);
        if should_scrub && !passes_passthrough {
            removed.insert(name);
            continue;
        }
        kept.push((name, value));
    }

    ScrubbedEnvironment {
        kept,
        removed: removed.into_iter().collect(),
    }
}

fn matches_any_pattern(candidate: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .filter(|pattern| !pattern.is_empty())
        .any(|pattern| wildcard_matches(pattern, candidate))
}

fn wildcard_matches(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let pattern_bytes = pattern.as_bytes();
    let candidate_bytes = candidate.as_bytes();

    let mut p = 0usize;
    let mut c = 0usize;
    let mut star_idx: Option<usize> = None;
    let mut match_after_star = 0usize;

    while c < candidate_bytes.len() {
        if p < pattern_bytes.len() && pattern_bytes[p] == candidate_bytes[c] {
            p += 1;
            c += 1;
            continue;
        }

        if p < pattern_bytes.len() && pattern_bytes[p] == b'*' {
            star_idx = Some(p);
            p += 1;
            match_after_star = c;
            continue;
        }

        if let Some(last_star_idx) = star_idx {
            p = last_star_idx + 1;
            match_after_star += 1;
            c = match_after_star;
            continue;
        }

        return false;
    }

    while p < pattern_bytes.len() && pattern_bytes[p] == b'*' {
        p += 1;
    }

    p == pattern_bytes.len()
}

#[cfg(test)]
mod tests {
    use super::{scrub_environment, wildcard_matches};

    #[test]
    fn removes_secret_variables_and_keeps_passthrough() {
        let vars = vec![
            ("AWS_SECRET_ACCESS_KEY".to_string(), "secret".to_string()),
            ("HOME".to_string(), "/Users/test".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ];
        let scrub_patterns = vec!["AWS_*".to_string(), "*_SECRET*".to_string()];
        let passthrough_patterns = vec!["HOME".to_string(), "PATH".to_string()];

        let scrubbed = scrub_environment(vars, &scrub_patterns, &passthrough_patterns);

        assert_eq!(scrubbed.removed, vec!["AWS_SECRET_ACCESS_KEY".to_string()]);
        assert!(scrubbed.kept.iter().any(|(name, _)| name == "HOME"));
        assert!(scrubbed.kept.iter().any(|(name, _)| name == "PATH"));
    }

    #[test]
    fn passthrough_pattern_overrides_scrub_pattern() {
        let vars = vec![
            ("NPM_TOKEN".to_string(), "token".to_string()),
            ("GITHUB_TOKEN".to_string(), "token2".to_string()),
        ];
        let scrub_patterns = vec!["*_TOKEN*".to_string()];
        let passthrough_patterns = vec!["NPM_*".to_string()];

        let scrubbed = scrub_environment(vars, &scrub_patterns, &passthrough_patterns);

        assert!(scrubbed.kept.iter().any(|(name, _)| name == "NPM_TOKEN"));
        assert_eq!(scrubbed.removed, vec!["GITHUB_TOKEN".to_string()]);
    }

    #[test]
    fn supports_wildcard_passthrough_patterns() {
        let vars = vec![
            ("LC_ALL".to_string(), "en_US.UTF-8".to_string()),
            ("XDG_CACHE_HOME".to_string(), "/tmp/cache".to_string()),
        ];
        let scrub_patterns = vec!["LC_*".to_string(), "XDG_*".to_string()];
        let passthrough_patterns = vec!["LC_*".to_string()];

        let scrubbed = scrub_environment(vars, &scrub_patterns, &passthrough_patterns);

        assert!(scrubbed.kept.iter().any(|(name, _)| name == "LC_ALL"));
        assert_eq!(scrubbed.removed, vec!["XDG_CACHE_HOME".to_string()]);
    }

    #[test]
    fn wildcard_matching_supports_infix_and_suffix_patterns() {
        assert!(wildcard_matches("AWS_*", "AWS_SECRET_ACCESS_KEY"));
        assert!(wildcard_matches("*_SECRET*", "AWS_SECRET_ACCESS_KEY"));
        assert!(wildcard_matches("*_KEY", "DATABASE_KEY"));
        assert!(!wildcard_matches("*_KEY", "DATABASE_KEY_EXTRA"));
        assert!(!wildcard_matches("SSH_AUTH_SOCK", "SSH_AUTH"));
    }
}
