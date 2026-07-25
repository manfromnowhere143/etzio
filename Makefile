.PHONY: demo test lint all

demo:
	python3 -m etzio.cli

test:
	python3 -m pytest -q

lint:
	ruff check etzio tests

all: lint test demo
