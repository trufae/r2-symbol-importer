PYTHON ?= python3
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
VENV = $(PREFIX)/lib/r2-symbol-importer

.PHONY: user-install user-uninstall

user-install:
	"$(PYTHON)" -m venv "$(VENV)"
	"$(VENV)/bin/python" -m pip install --upgrade .
	mkdir -p "$(BINDIR)"
	ln -fs "$(VENV)/bin/r2-symbol-importer" "$(BINDIR)/r2-symbol-importer"

user-uninstall:
	rm -f "$(BINDIR)/r2-symbol-importer"
	rm -rf "$(VENV)"
