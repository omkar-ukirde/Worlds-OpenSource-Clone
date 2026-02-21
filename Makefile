.PHONY: install install-dev install-training test lint format typecheck clean generate shell build publish

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

install-training:
	pip install -e ".[training]"

install-all:
	pip install -e ".[dev,training]"

# Quality
test:
	pytest tests/ -v --cov=openworlds --cov-report=term-missing

lint:
	ruff check openworlds/ tests/

format:
	ruff format openworlds/ tests/

typecheck:
	mypy openworlds/

# Quick commands
generate:
	openworlds manifest generate --hosts 20 --subnets 2 --seed 42 -o data/manifests/default.json

shell:
	openworlds shell --manifest data/manifests/default.json

# Packaging
build: clean
	python3 -m build

publish: build
	python3 -m twine upload dist/*

# Cleanup
clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
