# vmlinux.h

Kernel type definitions for CO-RE, one per architecture. Generated with the
vendored bpftool from Ubuntu 24.04 kernel `6.8.0-142-generic`:

| Directory | Source |
|---|---|
| `arm64/` | `/sys/kernel/btf/vmlinux` on a running arm64 6.8.0-142 kernel (`make -C sensor vmlinux`) |
| `x86/` | `.BTF` of the vmlinux ELF extracted from `linux-image-unsigned-6.8.0-142-generic_6.8.0-142.142_amd64.deb` |

CO-RE relocations adjust field offsets at load time, so these headers also work
on older kernels (5.15) as long as the fields used exist there.

The headers are per-architecture because some types (for example `pt_regs`)
differ between x86_64 and aarch64.
