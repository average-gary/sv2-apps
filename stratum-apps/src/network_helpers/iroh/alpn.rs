//! Per-role ALPN constants for SV2 over iroh.
//!
//! Each SV2 role registers exactly one ALPN on its iroh listener. Cross-role
//! accidental dials (e.g. a translator dialing a JDS) are rejected at the
//! QUIC layer before any SV2 bytes flow. The version suffix (`/0`) leaves
//! room for future protocol revisions to be negotiated independently per
//! role.
//!
//! Matches the 3-ALPN pattern used by Fedimint in production. See
//! `/Users/garykrause/.claude/plans/how-might-we-implement-snoopy-lollipop.md`
//! § "Per-role ALPN constants" for rationale.

/// ALPN for the pool's downstream listener (mining clients connect here).
pub const SV2_POOL_ALPN: &[u8] = b"sv2/pool/0";

/// ALPN for the Job Declarator Server's downstream listener.
pub const SV2_JDS_ALPN: &[u8] = b"sv2/jds/0";

/// ALPN for the Job Declarator Client's downstream listener.
pub const SV2_JDC_ALPN: &[u8] = b"sv2/jdc/0";

/// ALPN for the translator's upstream dial (translator dials a pool).
pub const SV2_TPROXY_ALPN: &[u8] = b"sv2/tproxy/0";

/// ALPN for the SV2 Template Provider listener (clients dialing TP register
/// this ALPN). Used by Pool→TP and JDC→TP outbound dials. The plan didn't
/// pre-define this site's ALPN; we add it here as the single source of truth
/// so all roles dialing a TP agree on the wire identifier.
pub const SV2_TP_ALPN: &[u8] = b"sv2/tp/0";
