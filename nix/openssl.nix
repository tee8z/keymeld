# Keep the native library patched independently of the Rust openssl crate.
# Release and checksum: https://openssl-library.org/source/
# https://github.com/openssl/openssl/releases/download/openssl-3.6.4/openssl-3.6.4.tar.gz.sha256
final: prev:
let
  version = "3.6.4";
in
{
  openssl_3_6 =
    if prev.lib.versionAtLeast prev.openssl_3_6.version version then
      prev.openssl_3_6
    else
      prev.openssl_3_6.overrideAttrs (old: {
        inherit version;
        # The bootstrap fetcher avoids a curl -> OpenSSL -> fetchurl cycle.
        src = prev.stdenv.fetchurlBoot {
          url = "https://github.com/openssl/openssl/releases/download/openssl-${version}/openssl-${version}.tar.gz";
          hash = "sha256-m/+qGtHgezVMIb0zJOwC+hVXn0Wn0ElLPnS8RJtzM+8=";
        };
        # OpenSSL reformatted this header after 3.6.0. Replace only the old
        # certificate-path hunk with an exact substitution for the new format.
        # Keep NIX_SSL_CERT_FILE, kernel detection, platform patches, and tests.
        patches = prev.lib.filter
          (patch: !(builtins.elem (builtins.baseNameOf (toString patch)) [
            "use-etc-ssl-certs.patch"
            "use-etc-ssl-certs-darwin.patch"
          ]))
          old.patches;
        postPatch = old.postPatch + ''
          substituteInPlace include/internal/common.h \
            --replace-fail '#define X509_CERT_FILE OPENSSLDIR "/cert.pem"' \
              '#define X509_CERT_FILE "${if prev.stdenv.hostPlatform.isDarwin then "/nix/var/nix/profiles/default/etc/ssl/certs/ca-bundle.crt" else "/etc/ssl/certs/ca-certificates.crt"}"'
        '';
        meta = old.meta // {
          changelog = "https://github.com/openssl/openssl/blob/openssl-${version}/CHANGES.md";
        };
      });
  openssl = final.openssl_3_6;
}
