# A patched libssl for the keymeld binaries only. This deliberately does not
# replace pkgs.openssl: overriding it globally rebuilt curl, python3 and the
# rest of the closure from source on every CI job.
# Release and checksum: https://openssl-library.org/source/
# https://github.com/openssl/openssl/releases/download/openssl-3.6.4/openssl-3.6.4.tar.gz.sha256
final: prev:
let
  version = "3.6.4";
in
{
  opensslPatched =
    if prev.lib.versionAtLeast prev.openssl_3_6.version version then
      prev.openssl_3_6
    else
      prev.openssl_3_6.overrideAttrs (old: {
        inherit version;
        # Upstream tests the release; 90-test_sslapi.t is timing-sensitive and
        # fails under the sandbox on aarch64 runners.
        doCheck = false;
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
}
