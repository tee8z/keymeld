The `aws-nitro-attestation.cose` fixture is an unmodified historical AWS Nitro
attestation from `nitro_attest` 0.2.0:

https://docs.rs/crate/nitro_attest/0.2.0/source/tests/fixtures/attestation.cose

Its MIT license is in `NITRO_ATTEST_LICENSE`. The certificate chain was valid at
Unix time 1736179625. The fixture has no client nonce and must never pass the
complete Keymeld verification policy. The regression test verifies its AWS
certificate chain and COSE signature before rejecting the missing nonce. Tests
also reject its expired certificates at the current test clock.

The trust anchor at `src/attestation/aws-nitro-root-g1.der` is the DER form of the
certificate in the AWS Nitro Root G1 bundle:

https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip

Its SHA-256 fingerprint is pinned in a regression test against the value in the
[AWS verification specification](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).
Synthetic test certificates and signatures are generated in Rust and are never
accepted through the production verifier API.
