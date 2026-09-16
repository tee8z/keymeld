# AWS KMS TLS roots

The enclave's strict KMS client trusts only these four Amazon Trust Services roots.
It does not load the host certificate store or an `SSL_CERT_FILE` override for KMS.

The PEM files came from the [Amazon Trust Services repository](https://www.amazontrust.com/repository/) on 2026-09-16.
Their SHA-256 subject-public-key hashes match the repository's published values:

| Certificate | SHA-256 SPKI |
| --- | --- |
| AmazonRootCA1.pem | `fbe3018031f9586bcbf41727e417b7d1c45c2f47f93be372a17b96b50757d5a2` |
| AmazonRootCA2.pem | `7f4296fc5b6a4e3b35d3c369623e364ab1af381d8fa7121533c9d6c633ea2461` |
| AmazonRootCA3.pem | `36abc32656acfc645c61b71613c4bf21c787f5cabbee48348d58597803d7abc9` |
| AmazonRootCA4.pem | `f7ecded5c66047d28ed6466b543c40e0743abe81d109254dcf845d4c2c7853c5` |

The Rust regression also pins the complete certificate fingerprints.
Review certificate updates as enclave code changes and publish the resulting image measurements.
These are public trust anchors, not private credentials.
