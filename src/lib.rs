// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! # Enclave Verifier
//!
//! Single-function WASM app that verifies a remote Privasys enclave over
//! RA-TLS.  All verification happens inside the enclave's egress client
//! (`enclave_os_egress::client::https_fetch`): we build an
//! `https::RaTlsPolicy` — the same WIT record that `enclave_os_egress`
//! exposes — and pass it to the single `fetch` host import. The handshake
//! succeeds iff every policy check passes.

#[allow(warnings)]
mod bindings;

use bindings::privasys::enclave_os::https;
use bindings::{ErrorCode, Guest, VerifyRequest, VerifyResult};

struct EnclaveVerifier;

impl Guest for EnclaveVerifier {
    fn verify(request: VerifyRequest) -> VerifyResult {
        let target = request.url.clone();

        if let Err(err) = validate_url(&target) {
            return fail(target, ErrorCode::InvalidUrl, err);
        }

        let policy = https::RatlsPolicy {
            tee: match request.tee {
                Some(bindings::TeeType::Tdx) => https::TeeType::Tdx,
                Some(bindings::TeeType::Sgx) | None => https::TeeType::Sgx,
            },
            mr_enclave: request.mr_enclave,
            mr_signer: request.mr_signer,
            mr_td: request.mr_td,
            challenge_nonce: request.challenge_nonce,
            expected_oids: request
                .oid_requirements
                .unwrap_or_default()
                .into_iter()
                .map(|o| https::ExpectedOid {
                    oid: o.oid,
                    value: o.expected_value,
                })
                .collect(),
            attestation_servers: request.attestation_servers.unwrap_or_default(),
        };

        let req = https::Request {
            method: https::Method::Head,
            url: target.clone(),
            headers: Vec::new(),
            body: None,
            ratls: Some(policy),
            ca_roots_der: request.ca_roots_der,
        };

        match https::fetch(&req) {
            Ok(_) => VerifyResult {
                success: true,
                error_code: None,
                error_message: None,
                target_url: target,
            },
            Err(msg) => fail(target, classify(&msg), msg),
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────

fn validate_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("url is empty".into());
    }
    if !url.starts_with("https://") {
        return Err("url must start with 'https://'".into());
    }
    Ok(())
}

fn fail(target_url: String, code: ErrorCode, msg: String) -> VerifyResult {
    VerifyResult {
        success: false,
        error_code: Some(code),
        error_message: Some(msg),
        target_url,
    }
}

/// Map a host error string to a structured [`ErrorCode`].  The host returns
/// free-form strings produced by `enclave-os-egress`; we match well-known
/// substrings so callers can distinguish the common failure modes.
fn classify(msg: &str) -> ErrorCode {
    let m = msg.to_ascii_lowercase();
    if m.contains("mrenclave mismatch")
        || m.contains("mrsigner mismatch")
        || m.contains("mrtd mismatch")
    {
        ErrorCode::MeasurementMismatch
    } else if m.contains("reportdata mismatch") {
        ErrorCode::ReportDataMismatch
    } else if m.contains("oid ") && (m.contains("not found") || m.contains("mismatch")) {
        ErrorCode::OidMismatch
    } else if m.contains("no sgx") || m.contains("no tdx") || m.contains("no attestation quote") {
        ErrorCode::QuoteMissingOrWrongTee
    } else if m.contains("invalid ca root") {
        ErrorCode::InvalidCaRoot
    } else if m.contains("attestation server") || m.contains("tcb_") {
        ErrorCode::AttestationServerRejected
    } else if m.contains("webpki") || m.contains("certificate") || m.contains("unknownissuer") {
        ErrorCode::TlsChainInvalid
    } else if m.contains("connect") || m.contains("network") {
        ErrorCode::ConnectionFailed
    } else {
        ErrorCode::Other
    }
}

bindings::export!(EnclaveVerifier with_types_in bindings);
