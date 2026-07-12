.PHONY: install dev test test-cov lint run clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

test-cov:
	pytest tests/ --cov=aws_compliance_mcp --cov-report=term-missing --cov-report=html

lint:
	ruff check src/ tests/

run:
	python -m aws_compliance_mcp.server

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	rm -rf htmlcov .coverage
