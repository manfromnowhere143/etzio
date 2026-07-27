.PHONY: demo test lint policy verify all

ETZIO_PYTHON ?= python3

demo:
	$(ETZIO_PYTHON) -m etzio.cli

test:
	$(ETZIO_PYTHON) -m pytest -q

lint:
	$(ETZIO_PYTHON) -m ruff check etzio tests scripts

policy:
	$(ETZIO_PYTHON) scripts/validate_repository.py

verify:
	bash scripts/ci/verify.sh

all: verify
