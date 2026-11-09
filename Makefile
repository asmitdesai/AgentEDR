# AgentEDR top-level targets (see CLAUDE.md).
#
# The sensor needs Linux. On macOS, `sensor` and `vm-test` run inside a Lima
# VM: bench/vm/lima-dev.yaml (instance agentedr, the default) or another one
# selected with LIMA_VM=..., e.g. agentedr-jammy (bench/vm/lima-jammy.yaml).

LIMA_VM  ?= agentedr
# Sensor mode for vm-test: auto | lsm | fentry.
MODE     ?= auto
UNAME_S  := $(shell uname -s)
MACHINE  := $(shell uname -m)
BIN_DIR  := src/agentedr/_bin
# In the Lima VM the repo is shared with macOS, so the Linux venv must live
# outside the tree (UV_PROJECT_ENVIRONMENT, set below when delegating).
VM_VENV  := /opt/agentedr-venv
VENV     := $(or $(UV_PROJECT_ENVIRONMENT),.venv)
# VM venvs use the lowest supported Python, not whatever uv would pick.
VM_PYTHON := 3.11
# Each machine (each Lima VM, each CI runner) builds the sensor into its own
# directory, sensor/build/<name>/, because all VMs share this tree. Inside a
# Lima VM the hostname is lima-<instance>, so <name> is the instance name.
BUILD_NAME ?= $(patsubst lima-%,%,$(shell hostname -s))
SENSOR_OUT := build/$(BUILD_NAME)

.PHONY: sensor dev test lint vm-test clean

ifeq ($(UNAME_S),Darwin)

sensor vm-test:
	limactl shell --workdir "$(CURDIR)" $(LIMA_VM) \
		env UV_PROJECT_ENVIRONMENT=$(VM_VENV) make $@ MODE=$(MODE)

else

sensor:
	@test -f sensor/libbpf/src/Makefile || git submodule update --init --recursive
	$(MAKE) -C sensor OUTPUT=$(SENSOR_OUT)
	mkdir -p $(BIN_DIR)
	install -m 0755 sensor/$(SENSOR_OUT)/agentedr-sensor-$(MACHINE) $(BIN_DIR)/

# vm-test depends on sensor, so each VM installs its own binary into
# $(BIN_DIR) right before its tests run.
vm-test: sensor
	uv sync --quiet --python $(VM_PYTHON)
	@# Tests run as root; PYTHONDONTWRITEBYTECODE keeps root-owned caches out
	@# of the user-owned venv (they would block the next uv sync).
	sudo env AGENTEDR_TEST_MODE=$(MODE) PYTHONDONTWRITEBYTECODE=1 \
		$(VENV)/bin/python -m pytest -v -p no:cacheprovider tests/integration

endif

dev:
	uv sync

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src

clean:
	rm -rf sensor/build $(BIN_DIR)
