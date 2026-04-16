use clawcrate_types::ResourceLimits;
use nix::sys::resource::{getrlimit, rlim_t, setrlimit, Resource, RLIM_INFINITY};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedRlimit {
    pub resource: &'static str,
    pub previous_soft: u64,
    pub effective_soft: u64,
    pub hard: u64,
    pub changed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RlimitError {
    #[error("failed to query {resource}: {source}")]
    Query {
        resource: &'static str,
        #[source]
        source: nix::Error,
    },
    #[error("failed to apply {resource}: {source}")]
    Apply {
        resource: &'static str,
        #[source]
        source: nix::Error,
    },
}

pub fn apply_resource_limits(limits: &ResourceLimits) -> Result<Vec<AppliedRlimit>, RlimitError> {
    let targets = build_targets(limits);
    let mut applied = Vec::with_capacity(targets.len());
    for (resource, label, desired_soft) in targets {
        applied.push(apply_soft_limit(resource, label, desired_soft)?);
    }
    Ok(applied)
}

fn build_targets(limits: &ResourceLimits) -> Vec<(Resource, &'static str, rlim_t)> {
    let mut targets = vec![
        (
            Resource::RLIMIT_CPU,
            "RLIMIT_CPU",
            u64_to_rlim(limits.max_cpu_seconds),
        ),
        (
            Resource::RLIMIT_AS,
            "RLIMIT_AS",
            u64_to_rlim(memory_mb_to_bytes(limits.max_memory_mb)),
        ),
        (
            Resource::RLIMIT_NOFILE,
            "RLIMIT_NOFILE",
            u64_to_rlim(limits.max_open_files),
        ),
        (
            Resource::RLIMIT_FSIZE,
            "RLIMIT_FSIZE",
            u64_to_rlim(limits.max_output_bytes),
        ),
    ];
    push_process_limit_target(&mut targets, limits);
    targets
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn push_process_limit_target(
    targets: &mut Vec<(Resource, &'static str, rlim_t)>,
    limits: &ResourceLimits,
) {
    targets.push((
        Resource::RLIMIT_NPROC,
        "RLIMIT_NPROC",
        u64_to_rlim(limits.max_processes),
    ));
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn push_process_limit_target(
    _targets: &mut Vec<(Resource, &'static str, rlim_t)>,
    _limits: &ResourceLimits,
) {
}

fn apply_soft_limit(
    resource: Resource,
    label: &'static str,
    desired_soft: rlim_t,
) -> Result<AppliedRlimit, RlimitError> {
    let (current_soft, current_hard) =
        getrlimit(resource).map_err(|source| RlimitError::Query {
            resource: label,
            source,
        })?;
    let effective_soft = clamp_to_hard_limit(desired_soft, current_hard);
    let changed = effective_soft != current_soft;
    if changed {
        setrlimit(resource, effective_soft, current_hard).map_err(|source| RlimitError::Apply {
            resource: label,
            source,
        })?;
    }

    Ok(AppliedRlimit {
        resource: label,
        previous_soft: rlim_to_u64(current_soft),
        effective_soft: rlim_to_u64(effective_soft),
        hard: rlim_to_u64(current_hard),
        changed,
    })
}

fn clamp_to_hard_limit(desired_soft: rlim_t, hard: rlim_t) -> rlim_t {
    if hard == RLIM_INFINITY {
        desired_soft
    } else {
        desired_soft.min(hard)
    }
}

fn memory_mb_to_bytes(memory_mb: u64) -> u64 {
    memory_mb.saturating_mul(1024).saturating_mul(1024)
}

fn u64_to_rlim(value: u64) -> rlim_t {
    rlim_t::try_from(value).unwrap_or(rlim_t::MAX)
}

fn rlim_to_u64(value: rlim_t) -> u64 {
    let widened: u128 = value.into();
    widened.min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::{
        apply_soft_limit, build_targets, clamp_to_hard_limit, memory_mb_to_bytes, u64_to_rlim,
    };
    use clawcrate_types::ResourceLimits;
    use nix::sys::resource::{getrlimit, rlim_t, Resource, RLIM_INFINITY};

    #[test]
    fn maps_resource_limits_into_expected_targets() {
        let limits = ResourceLimits {
            max_cpu_seconds: 60,
            max_memory_mb: 2048,
            max_open_files: 1024,
            max_processes: 128,
            max_output_bytes: 1_048_576,
        };

        let targets = build_targets(&limits);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(targets.len(), 5);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        assert_eq!(targets.len(), 4);
        assert_eq!(targets[0].1, "RLIMIT_CPU");
        assert_eq!(targets[0].2, u64_to_rlim(60));
        assert_eq!(targets[1].1, "RLIMIT_AS");
        assert_eq!(targets[1].2, u64_to_rlim(2_147_483_648));
        assert_eq!(targets[2].1, "RLIMIT_NOFILE");
        assert_eq!(targets[2].2, u64_to_rlim(1024));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            assert_eq!(targets[3].1, "RLIMIT_FSIZE");
            assert_eq!(targets[3].2, u64_to_rlim(1_048_576));
            assert_eq!(targets[4].1, "RLIMIT_NPROC");
            assert_eq!(targets[4].2, u64_to_rlim(128));
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            assert_eq!(targets[3].1, "RLIMIT_FSIZE");
            assert_eq!(targets[3].2, u64_to_rlim(1_048_576));
        }
    }

    #[test]
    fn memory_conversion_is_saturating() {
        assert_eq!(memory_mb_to_bytes(1), 1_048_576);
        assert_eq!(memory_mb_to_bytes(u64::MAX), u64::MAX);
    }

    #[test]
    fn clamp_respects_hard_limit() {
        assert_eq!(clamp_to_hard_limit(200, 100), 100);
        assert_eq!(clamp_to_hard_limit(50, 100), 50);
        assert_eq!(clamp_to_hard_limit(50, RLIM_INFINITY), 50);
    }

    #[test]
    fn apply_soft_limit_is_noop_when_desired_equals_current_soft_limit() {
        let (soft, _) = getrlimit(Resource::RLIMIT_NOFILE).expect("query RLIMIT_NOFILE");
        let applied = apply_soft_limit(Resource::RLIMIT_NOFILE, "RLIMIT_NOFILE", soft)
            .expect("apply RLIMIT_NOFILE");
        assert!(!applied.changed);
        assert_eq!(applied.previous_soft, applied.effective_soft);
    }

    #[test]
    fn u64_to_rlim_clamps_to_target_type_max() {
        assert_eq!(u64_to_rlim(u64::MAX), rlim_t::MAX);
    }
}
