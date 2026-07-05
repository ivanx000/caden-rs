//! Typed accessors for WebAuthn authenticator extensions (§10.5).
//!
//! The three most common extensions are modeled here:
//!
//! - [`CredProps`] (`"credProps"`) — whether the credential is a resident key /
//!   discoverable credential (§10.4)
//! - `appid` — whether the legacy U2F appId extension was applied (§10.1)
//! - [`PrfExtension`] (`"prf"`) — pseudo-random function output for client-side
//!   secret derivation
//!
//! Obtain a typed view from a ceremony result:
//!
//! ```rust,ignore
//! if let Some(ext) = reg_result.extensions() {
//!     if let Some(cp) = ext.cred_props() {
//!         println!("resident key: {:?}", cp.rk);
//!     }
//!     if let Some(used) = ext.appid() {
//!         println!("appId substituted: {used}");
//!     }
//! }
//! ```

use std::collections::HashMap;

use ciborium::value::Value;

// ─── Public types ─────────────────────────────────────────────────────────────

/// Typed credential properties returned by the `credProps` extension (§10.4).
///
/// `rk` indicates whether the credential was created as a resident /
/// discoverable credential. `None` means the authenticator did not include
/// this field in the extension response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredProps {
    /// Whether the credential is stored as a discoverable credential.
    ///
    /// `Some(true)` — stored as discoverable; `Some(false)` — not discoverable;
    /// `None` — the authenticator omitted this field.
    pub rk: Option<bool>,
}

/// PRF output values from the `prf` extension.
///
/// `first` corresponds to the first PRF evaluation; `second` is only present
/// when a second evaluation was requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfValues {
    /// Output bytes for the first PRF input.
    pub first: Vec<u8>,
    /// Output bytes for the second PRF input, or `None` if only one was requested.
    pub second: Option<Vec<u8>>,
}

/// Typed result of the `prf` extension.
///
/// `results` is `None` when the authenticator processed the extension but
/// returned no output (common during registration when the RP has not yet
/// supplied PRF inputs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfExtension {
    /// PRF output values, if the authenticator returned them.
    pub results: Option<PrfValues>,
}

/// A typed view over the raw authenticator extension map.
///
/// Obtain this via [`crate::RegistrationResult::extensions`] or
/// [`crate::AuthenticationResult::extensions`]. Each accessor returns `None`
/// when the extension is absent or the CBOR does not match the expected
/// structure. Unknown extensions remain accessible via the raw `extensions`
/// field on the result struct.
#[derive(Debug)]
pub struct ExtensionView<'a> {
    map: &'a HashMap<String, Value>,
}

impl<'a> ExtensionView<'a> {
    pub(crate) fn new(map: &'a HashMap<String, Value>) -> Self {
        Self { map }
    }

    /// Extract the `credProps` extension value, if present (§10.4).
    ///
    /// Returns `None` if the extension is absent or the CBOR value is not a map.
    /// When present, `CredProps::rk` is `None` if the authenticator omitted the
    /// `rk` field or if `rk` is not a bool.
    pub fn cred_props(&self) -> Option<CredProps> {
        let value = self.map.get("credProps")?;
        let map = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let rk = find_bool(map, "rk");
        Some(CredProps { rk })
    }

    /// Extract the `appid` extension value, if present (§10.1).
    ///
    /// Returns `Some(true)` if the legacy U2F appId substitution was applied,
    /// `Some(false)` if the extension was present but not applied, or `None`
    /// if the extension is absent or has an unexpected CBOR type.
    pub fn appid(&self) -> Option<bool> {
        match self.map.get("appid")? {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Extract the `prf` extension value, if present.
    ///
    /// Returns `None` if the extension is absent or the outer CBOR value is not
    /// a map. Returns `Some(PrfExtension { results: None })` when the authenticator
    /// processed the extension but included no output. Returns `None` when the
    /// inner `results` map is present but `first` is absent or not bytes.
    pub fn prf(&self) -> Option<PrfExtension> {
        let outer = match self.map.get("prf")? {
            Value::Map(m) => m,
            _ => return None,
        };

        let results = match find_value(outer, "results") {
            None => None,
            Some(Value::Map(inner)) => {
                let first = find_bytes(inner, "first")?;
                let second = find_bytes(inner, "second");
                Some(PrfValues { first, second })
            }
            _ => return None,
        };

        Some(PrfExtension { results })
    }
}

// ─── CBOR map helpers ─────────────────────────────────────────────────────────

fn find_value<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| {
        if matches!(k, Value::Text(s) if s == key) {
            Some(v)
        } else {
            None
        }
    })
}

fn find_bool(map: &[(Value, Value)], key: &str) -> Option<bool> {
    match find_value(map, key)? {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

fn find_bytes(map: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    match find_value(map, key)? {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    // ── cred_props ────────────────────────────────────────────────────────────

    #[test]
    fn cred_props_rk_true() {
        let inner = Value::Map(vec![(Value::Text("rk".to_string()), Value::Bool(true))]);
        let map = make_map(&[("credProps", inner)]);
        let view = ExtensionView::new(&map);
        assert_eq!(view.cred_props(), Some(CredProps { rk: Some(true) }));
    }

    #[test]
    fn cred_props_rk_false() {
        let inner = Value::Map(vec![(Value::Text("rk".to_string()), Value::Bool(false))]);
        let map = make_map(&[("credProps", inner)]);
        let view = ExtensionView::new(&map);
        assert_eq!(view.cred_props(), Some(CredProps { rk: Some(false) }));
    }

    #[test]
    fn cred_props_rk_absent_gives_none_rk() {
        let inner = Value::Map(vec![]);
        let map = make_map(&[("credProps", inner)]);
        let view = ExtensionView::new(&map);
        assert_eq!(view.cred_props(), Some(CredProps { rk: None }));
    }

    #[test]
    fn cred_props_rk_wrong_type_gives_none_rk() {
        let inner = Value::Map(vec![(
            Value::Text("rk".to_string()),
            Value::Integer(1i64.into()),
        )]);
        let map = make_map(&[("credProps", inner)]);
        let view = ExtensionView::new(&map);
        assert_eq!(view.cred_props(), Some(CredProps { rk: None }));
    }

    #[test]
    fn cred_props_value_not_a_map_returns_none() {
        let map = make_map(&[("credProps", Value::Bool(true))]);
        let view = ExtensionView::new(&map);
        assert!(view.cred_props().is_none());
    }

    #[test]
    fn cred_props_absent_returns_none() {
        let map = make_map(&[]);
        let view = ExtensionView::new(&map);
        assert!(view.cred_props().is_none());
    }

    // ── appid ─────────────────────────────────────────────────────────────────

    #[test]
    fn appid_true() {
        let map = make_map(&[("appid", Value::Bool(true))]);
        let view = ExtensionView::new(&map);
        assert_eq!(view.appid(), Some(true));
    }

    #[test]
    fn appid_false() {
        let map = make_map(&[("appid", Value::Bool(false))]);
        let view = ExtensionView::new(&map);
        assert_eq!(view.appid(), Some(false));
    }

    #[test]
    fn appid_absent_returns_none() {
        let map = make_map(&[]);
        let view = ExtensionView::new(&map);
        assert!(view.appid().is_none());
    }

    #[test]
    fn appid_wrong_type_returns_none() {
        let map = make_map(&[("appid", Value::Integer(1i64.into()))]);
        let view = ExtensionView::new(&map);
        assert!(view.appid().is_none());
    }

    // ── prf ───────────────────────────────────────────────────────────────────

    #[test]
    fn prf_with_first_only() {
        let inner = Value::Map(vec![(
            Value::Text("results".to_string()),
            Value::Map(vec![(
                Value::Text("first".to_string()),
                Value::Bytes(vec![0xAA, 0xBB]),
            )]),
        )]);
        let map = make_map(&[("prf", inner)]);
        let view = ExtensionView::new(&map);
        let prf = view.prf().expect("expected prf");
        let results = prf.results.expect("expected results");
        assert_eq!(results.first, vec![0xAA, 0xBB]);
        assert!(results.second.is_none());
    }

    #[test]
    fn prf_with_first_and_second() {
        let inner = Value::Map(vec![(
            Value::Text("results".to_string()),
            Value::Map(vec![
                (
                    Value::Text("first".to_string()),
                    Value::Bytes(vec![0x01, 0x02]),
                ),
                (
                    Value::Text("second".to_string()),
                    Value::Bytes(vec![0x03, 0x04]),
                ),
            ]),
        )]);
        let map = make_map(&[("prf", inner)]);
        let view = ExtensionView::new(&map);
        let prf = view.prf().expect("expected prf");
        let results = prf.results.expect("expected results");
        assert_eq!(results.first, vec![0x01, 0x02]);
        assert_eq!(results.second, Some(vec![0x03, 0x04]));
    }

    #[test]
    fn prf_without_results_key() {
        let inner = Value::Map(vec![]);
        let map = make_map(&[("prf", inner)]);
        let view = ExtensionView::new(&map);
        let prf = view.prf().expect("expected prf");
        assert!(prf.results.is_none());
    }

    #[test]
    fn prf_absent_returns_none() {
        let map = make_map(&[]);
        let view = ExtensionView::new(&map);
        assert!(view.prf().is_none());
    }

    #[test]
    fn prf_outer_not_a_map_returns_none() {
        let map = make_map(&[("prf", Value::Bool(true))]);
        let view = ExtensionView::new(&map);
        assert!(view.prf().is_none());
    }

    #[test]
    fn prf_results_not_a_map_returns_none() {
        let inner = Value::Map(vec![(
            Value::Text("results".to_string()),
            Value::Bool(true),
        )]);
        let map = make_map(&[("prf", inner)]);
        let view = ExtensionView::new(&map);
        assert!(view.prf().is_none());
    }

    #[test]
    fn prf_results_missing_first_returns_none() {
        // "results" map present but "first" absent — `first` is required
        let inner = Value::Map(vec![(
            Value::Text("results".to_string()),
            Value::Map(vec![(
                Value::Text("second".to_string()),
                Value::Bytes(vec![0x03, 0x04]),
            )]),
        )]);
        let map = make_map(&[("prf", inner)]);
        let view = ExtensionView::new(&map);
        assert!(view.prf().is_none());
    }

    // ── cross-extension isolation ─────────────────────────────────────────────

    #[test]
    fn unknown_extension_does_not_affect_known_accessors() {
        let cp = Value::Map(vec![(Value::Text("rk".to_string()), Value::Bool(true))]);
        let map = make_map(&[
            ("credProps", cp),
            ("unknownExtension", Value::Integer(42i64.into())),
        ]);
        let view = ExtensionView::new(&map);
        assert!(view.cred_props().is_some());
        assert!(view.appid().is_none());
        assert!(view.prf().is_none());
    }
}
