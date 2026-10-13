# SPDX-License-Identifier: Apache-2.0
#
# Builds the AgentEDR sensor:
#   1. libbpf (vendored submodule) as a static library plus its headers
#   2. bpftool (vendored submodule), bootstrap flavour, used only at build time
#   3. bpf/agentedr.bpf.c -> agentedr.bpf.o (clang -target bpf, CO-RE)
#   4. agentedr.bpf.o -> agentedr.skel.h (bpftool gen skeleton)
#   5. src/*.c + skeleton -> static agentedr-sensor-<machine>
#
# Run on Linux. The binary is named after `uname -m` (x86_64, aarch64), which is
# what the engine's supervisor looks for.

MACHINE  ?= $(shell uname -m)
# Kernel-style arch name used by vmlinux.h directories and __TARGET_ARCH_*.
ARCH     := $(patsubst x86_64,x86,$(patsubst aarch64,arm64,$(MACHINE)))

OUTPUT   := build
LIBBPF_SRC  := $(abspath libbpf/src)
BPFTOOL_SRC := $(abspath bpftool/src)
LIBBPF_OBJ  := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUT := $(abspath $(OUTPUT)/bpftool)/
BPFTOOL     := $(BPFTOOL_OUT)bootstrap/bpftool
VMLINUX_DIR := bpf/vmlinux/$(ARCH)
TARGET      := $(OUTPUT)/agentedr-sensor-$(MACHINE)

CLANG    ?= clang
CC       ?= cc
CFLAGS   ?= -g -O2
CFLAGS   += -Wall -Wextra -std=gnu11 -I$(OUTPUT) -Isrc -Ibpf
# libelf on current Ubuntu pulls in zstd; order matters for static linking.
LDLIBS   := $(LIBBPF_OBJ) -lelf -lz -lzstd
LDFLAGS  += -static

SRCS     := $(wildcard src/*.c)
OBJS     := $(patsubst src/%.c,$(OUTPUT)/%.o,$(SRCS))
BPF_HDRS := bpf/events.h bpf/maps.h $(VMLINUX_DIR)/vmlinux.h

.PHONY: all clean vmlinux
all: $(TARGET)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUT):
	mkdir -p $@

# `install` with empty LIBDIR/INCLUDEDIR puts libbpf.a at build/libbpf.a and
# the public headers under build/bpf/, so `#include <bpf/libbpf.h>` works with -Ibuild.
$(LIBBPF_OBJ): | $(OUTPUT)/libbpf
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(abspath $(OUTPUT)/libbpf) DESTDIR=$(abspath $(OUTPUT)) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(BPFTOOL): | $(BPFTOOL_OUT)
	$(MAKE) -C $(BPFTOOL_SRC) OUTPUT=$(BPFTOOL_OUT) bootstrap

# vmlinux.h is committed. This target regenerates it from the running kernel;
# the committed copies come from Ubuntu 24.04 6.8 kernels (see bpf/vmlinux/README.md).
vmlinux: $(BPFTOOL)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_DIR)/vmlinux.h

$(OUTPUT)/agentedr.bpf.o: bpf/agentedr.bpf.c $(BPF_HDRS) $(LIBBPF_OBJ) | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(OUTPUT) -I$(VMLINUX_DIR) -Ibpf -c $< -o $@
	llvm-strip -g $@  # drop DWARF, keep BTF: smaller embedded object

$(OUTPUT)/agentedr.skel.h: $(OUTPUT)/agentedr.bpf.o $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< name agentedr_bpf > $@

$(OUTPUT)/%.o: src/%.c $(wildcard src/*.h) bpf/events.h $(OUTPUT)/agentedr.skel.h $(LIBBPF_OBJ)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) $(LIBBPF_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) $(LDLIBS) -o $@

clean:
	rm -rf $(OUTPUT)
