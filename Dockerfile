# Build android-doctor, then ship only the binary on a glibc distroless base.
# The build stage needs a C compiler: build.rs compiles the vendored brotli sources.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin android-doctor \
    && strip target/release/android-doctor

# distroless/cc carries glibc + libgcc for the dynamically linked binary, and nothing else:
# no shell, no package manager. android-doctor never loop-mounts, so it runs fully unprivileged.
FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/android-doctor /usr/local/bin/android-doctor
ENTRYPOINT ["android-doctor"]
