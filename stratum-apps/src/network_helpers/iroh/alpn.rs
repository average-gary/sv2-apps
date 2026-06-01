//! Per-role ALPN constants for SV2 over iroh.
//!
//! Each SV2 role registers exactly one ALPN on its iroh listener. Cross-role
//! accidental dials (e.g. a translator dialing a JDS) are rejected at the
//! QUIC layer before any SV2 bytes flow.
//!
//! # Versioning policy
//!
//! All five ALPN constants share a single [`SV2_WIRE_VERSION`] suffix. The
//! SV2 wire format is one protocol — when it changes, every role must
//! agree on the new version, so versioning per-role would just create
//! states where some roles speak `v0` and others speak `v1` and dials silently
//! fail the QUIC ALPN check. Bumping `SV2_WIRE_VERSION` moves all five
//! constants in lockstep.
//!
//! Matches the 3-ALPN pattern used by Fedimint in production.

/// SV2-over-iroh wire version. Bump when (and only when) the SV2 wire
/// protocol changes. All five role ALPNs below carry this suffix — they
/// must move together.
pub const SV2_WIRE_VERSION: u8 = 0;

/// ALPN for the pool's downstream listener (mining clients connect here).
pub const SV2_POOL_ALPN: &[u8] = b"sv2/pool/0";

/// ALPN for the Job Declarator Server's downstream listener.
pub const SV2_JDS_ALPN: &[u8] = b"sv2/jds/0";

/// ALPN for the Job Declarator Client's downstream listener.
pub const SV2_JDC_ALPN: &[u8] = b"sv2/jdc/0";

/// ALPN for the translator's upstream dial (translator dials a pool).
pub const SV2_TPROXY_ALPN: &[u8] = b"sv2/tproxy/0";

/// ALPN for the SV2 Template Provider listener (clients dialing TP register
/// this ALPN). Used by Pool→TP and JDC→TP outbound dials.
pub const SV2_TP_ALPN: &[u8] = b"sv2/tp/0";

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time-ish assertion that every ALPN ends with the digit form of
    /// `SV2_WIRE_VERSION`. If you bump the version, this fails until you
    /// update all five constants together — that's the point.
    #[test]
    fn alpn_suffixes_match_wire_version() {
        let suffix = format!("/{}", SV2_WIRE_VERSION);
        for alpn in [
            SV2_POOL_ALPN,
            SV2_JDS_ALPN,
            SV2_JDC_ALPN,
            SV2_TPROXY_ALPN,
            SV2_TP_ALPN,
        ] {
            let s = std::str::from_utf8(alpn).expect("ALPN is ASCII");
            assert!(
                s.ends_with(&suffix),
                "ALPN {s:?} does not end with /{} — bump SV2_WIRE_VERSION and \
                 every ALPN constant together",
                SV2_WIRE_VERSION
            );
        }
    }
}
