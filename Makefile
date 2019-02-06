venv/bin/python:
	virtualenv venv
	venv/bin/pip install -r requirements.txt

.PHONY: install
install: venv/bin/python
	venv/bin/python setup.py install

.PHONY: check
check: test lint

.PHONY: test
test: venv/bin/python
	venv/bin/python setup.py test

.PHONY: lint
lint:
	venv/bin/flake8 rulesengine_client

.PHONY: clean
clean:
	rm -rf venv build dist .eggs rulesengine_client.egg-info
	find rulesengine_client/ -name __pycache__ -or -name "*.py[co]" -exec rm -rf {} \;
