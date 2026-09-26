# The gateway image, assembled from the release's own gateway binary (the one
# in the release tarball) and the assets its build generated. Nothing compiles
# here, and with no RUN step the arm64 image builds on an amd64 runner without
# emulation. See the build-gateway-images job in .github/workflows/release.yml.
#
# Only the gateway images are built this way. The enclave images stay Nix
# builds (.#docker-enclave): they are the base that scripts/build-enclave-eif.sh
# measures, so they must be exactly what the flake builds.
#
# Build context (made by the release workflow), per architecture:
#   <arch>/keymeld-gateway                       the release binary
#   <arch>/share/{static,migrations,config}/     runtime assets
FROM gcr.io/distroless/cc-debian13@sha256:4594d59540d1948417f6ca2829ddd9294493a7c68b7528f4dd459de7f203a750
ARG TARGETARCH
# /bin is /usr/bin here, so /bin/keymeld-gateway resolves as in the Nix image.
COPY ${TARGETARCH}/keymeld-gateway /usr/bin/keymeld-gateway
COPY ${TARGETARCH}/share/ /usr/share/keymeld-gateway/
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    RUST_LOG=info \
    TEST_MODE=true \
    KEYMELD_STATIC_DIR=/usr/share/keymeld-gateway/static
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8090
CMD ["/usr/bin/keymeld-gateway"]
