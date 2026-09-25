# Makefile — the make surface for the frameprism ship gate.
#
# THIN DISPATCH ONLY: this file carries NO gate logic — no suite
# counts, no byte totals, no assertions of any gate outcome. Every
# target invokes an existing ci/*.sh sub-script (with --repo "$(REPO)")
# or a bare cargo command from tool/; the single source of gate truth
# stays ci/check.sh (and its sub-scripts). The syntax is the
# intersection of the macOS /usr/bin/make and the CI GNU make (3.81+).

REPO := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.DEFAULT_GOAL := check
.PHONY: check pins oracle108 xcheck audit fuzz build test clippy help

# The full ship gate — exactly `bash ci/check.sh` (the default goal).
check:
	bash ci/check.sh

# The granular targets: the five gate sub-scripts (1:1, --repo pinned).
pins:
	bash ci/check-pins.sh --repo "$(REPO)"

oracle108:
	bash ci/check-108.sh --repo "$(REPO)"

xcheck:
	bash ci/check-xcheck.sh --repo "$(REPO)"

audit:
	bash ci/check-audit.sh --repo "$(REPO)"

fuzz:
	bash ci/check-fuzz.sh --repo "$(REPO)"

# The three cargo commands (from tool/; no gate assertion here — the
# assertions are ci/check.sh's).
build:
	cd tool/ && cargo build --release

test:
	cd tool/ && cargo test --release --lib

clippy:
	cd tool/ && cargo clippy --workspace -- -D warnings

# The self-documenting summary (static recipe text; no logic).
help:
	@echo "frameprism ship gate — the make surface (thin dispatch; no gate logic here — the gate logic is in ci/check.sh)"
	@echo ""
	@echo "  check      the full ship gate (the default goal) — exactly 'bash ci/check.sh'"
	@echo "  pins       ci/check-pins.sh — the version pins"
	@echo "  oracle108  ci/check-108.sh — the 10/8-bit JXL oracle"
	@echo "  xcheck     ci/check-xcheck.sh — the JXL independent-decoder cross-check"
	@echo "  audit      ci/check-audit.sh — the offline dependency audit"
	@echo "  fuzz       ci/check-fuzz.sh — the C-boundary fuzz corpus"
	@echo "  build      cargo build --release (from tool/)"
	@echo "  test       cargo test --release --lib (from tool/)"
	@echo "  clippy     cargo clippy --workspace -- -D warnings (from tool/)"
	@echo "  help       this summary"
	@echo ""
	@echo "(the inline ci/check.sh steps with no sub-script — the README doc-drift"
	@echo " gate, the 10-frame oracle — have no make target)"
