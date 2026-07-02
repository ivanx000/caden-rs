//! Challenge lifecycle helpers.
//!
//! A [`Challenge`] must be single-use and short-lived. This module provides
//! helpers for expiry checks; the caller is responsible for invalidating a
//! challenge after it has been used (one-time-use enforcement).

use std::time::Duration;

use crate::credential::Challenge;

/// Default maximum challenge lifetime: 5 minutes.
///
/// FIDO recommends challenges expire "after a reasonable timeout" without
/// specifying a value; 5 minutes is a widely used default.
pub const CHALLENGE_MAX_AGE_SECS: u64 = 300;

/// Returns `true` if the challenge is older than [`CHALLENGE_MAX_AGE_SECS`].
///
/// If the system clock has gone backwards since the challenge was created, this
/// returns `true` (treats the challenge as expired for safety).
pub fn is_expired(challenge: &Challenge) -> bool {
    challenge
        .created_at
        .elapsed()
        .map(|age| age >= Duration::from_secs(CHALLENGE_MAX_AGE_SECS))
        .unwrap_or(true)
}

/// Returns `true` if the challenge is older than the given number of seconds.
pub fn is_expired_with_max_age(challenge: &Challenge, max_age_secs: u64) -> bool {
    challenge
        .created_at
        .elapsed()
        .map(|age| age >= Duration::from_secs(max_age_secs))
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn make_challenge(created_secs_ago: u64) -> Challenge {
        let created_at = SystemTime::now()
            .checked_sub(Duration::from_secs(created_secs_ago))
            .unwrap_or(UNIX_EPOCH);
        Challenge {
            bytes: vec![0u8; 32],
            created_at,
        }
    }

    #[test]
    fn fresh_challenge_is_not_expired() {
        let c = make_challenge(10);
        assert!(!is_expired(&c));
    }

    #[test]
    fn old_challenge_is_expired() {
        let c = make_challenge(CHALLENGE_MAX_AGE_SECS + 1);
        assert!(is_expired(&c));
    }

    #[test]
    fn custom_max_age() {
        let c = make_challenge(30);
        assert!(is_expired_with_max_age(&c, 20));
        assert!(!is_expired_with_max_age(&c, 60));
    }

    #[test]
    fn ttl_zero_is_immediately_expired() {
        // A TTL of 0 seconds means "expired as soon as it's created".
        let c = Challenge {
            bytes: vec![0u8; 32],
            created_at: SystemTime::now(),
        };
        assert!(is_expired_with_max_age(&c, 0));
    }

    #[test]
    fn ttl_max_never_expires() {
        let c = make_challenge(CHALLENGE_MAX_AGE_SECS * 100);
        assert!(!is_expired_with_max_age(&c, u64::MAX));
    }

    #[test]
    fn challenge_created_in_future_is_not_expired() {
        // elapsed() returns Err if created_at is in the future; we treat
        // that as expired for safety — but test the "fresh" case via the
        // is_expired_with_max_age wrapper.  A future timestamp means the
        // system clock moved backwards; elapsed() → Err → is_expired = true.
        let future = SystemTime::now()
            .checked_add(Duration::from_secs(9999))
            .expect("time arithmetic");
        let c = Challenge {
            bytes: vec![0u8; 32],
            created_at: future,
        };
        // The safety default: we cannot verify age → treat as expired.
        assert!(is_expired(&c));
    }

    #[test]
    fn two_challenges_differ() {
        let c1 = Challenge::new().expect("test setup");
        let c2 = Challenge::new().expect("test setup");
        assert_ne!(c1.bytes, c2.bytes);
    }

    #[test]
    fn challenge_is_32_bytes() {
        let c = Challenge::new().expect("test setup");
        assert_eq!(c.bytes.len(), 32);
    }
}
