# Binwalk extraction worker image

This image is the tool boundary used by `ContainerBinwalkWorker`. It is not the
FirmAtlas application image and must never be run inside the API or mapper
process.

The build pins:

- the Ubuntu 24.04 multi-platform image index by digest;
- ReFirmLabs Binwalk v3.1.0 source commit
  `4fdab3d464d97b68e0af9088df3f9e2e1545b21c`;
- Rust 1.82.0 and Cargo's committed lock file;
- sasquatch v4.5.1-4 release assets by architecture-specific SHA-256 and the
  Python filesystem extractor versions/commits.

Build the image, inspect its content-addressed ID, and use only that `sha256:`
value in the worker configuration:

```sh
docker build --pull --platform linux/arm64 \
  -t firmatlas/binwalk:v3.1.0 containers/binwalk
docker image inspect firmatlas/binwalk:v3.1.0 --format '{{.Id}}'
```

Runtime invariants are applied by the Python Adapter rather than this image:
no network, read-only root filesystem and input mount, writable derived-output
mount only, dropped capabilities, `no-new-privileges`, PID/CPU/memory limits,
wall-clock/file/byte budgets, and bounded logs. The output byte/file budgets
are supervised limits; a run that crosses either limit is rejected even if the
container exits before the next polling interval.

The repository recipe is the release source of truth. A locally built image is
not a released toolchain until its digest, probe result, and representative raw
firmware replay have been recorded in the mapping progress ledger.
