# AgentEDR top-level targets (see CLAUDE.md).
#
# The sensor needs Linux. On macOS, `sensor` and `vm-test` run inside the
# Lima VM defined in bench/vm/lima-dev.yaml (instance name: $(LIMA_VM)).

LIMA_VM  ?= agentedr
UNAME_S  := $(shell uname -s)
MACHINE  := $(shell uname -m)
BIN_DIR  := src/agentedr/_bin
# In the Lima VM the repo is shared with macOS, so the Linux venv must live
# outside the tree (UV_PROJECT_ENVIRONMENT, set below when delegating).
VM_VENV  := /opt/agentedr-venv
VENV     := $(or $(UV_PROJECT_ENVIRONMENT),.venv)

.PHONY: sensor dev test lint vm-test clean

ifeq ($(UNAME_S),Darwin)

sensor vm-test:
	limactl shell --workdir "$(CURDIR)" $(LIMA_VM) \
		env UV_PROJECT_ENVIRONMENT=$(VM_VENV) make $@

else

sensor:
	@test -f sensor/libbpf/src/Makefile || git submodule update --init --recursive
	$(MAKE) -C sensor
	mkdir -p $(BIN_DIR)
	install -m 0755 sensor/build/agentedr-sensor-$(MACHINE) $(BIN_DIR)/

vm-test: sensor
	uv sync --quiet
	sudo $(VENV)/bin/python -m pytest -v tests/integration

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
