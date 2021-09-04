.PHONY: clean
clean: clean-build clean-pyc

.PHONY: clean-build
clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr *.egg-info

.PHONY: clean-pyc
clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

.PHONY: lint
lint:
	tox -e lint

.PHONY: lint-roll
lint-roll:
	isort rest_framework_dynamicjwt tests
	$(MAKE) lint

.PHONY: tests
test:
	pytest tests

.PHONY: test-all
test-all:
	tox

.PHONY: build-docs
build-docs:
	sphinx-apidoc -o docs/ . \
		setup.py \
		*confest* \
		tests/* \
		rest_framework_dynamicjwt/token_blacklist/* \
		rest_framework_dynamicjwt/backends.py \
		rest_framework_dynamicjwt/compat.py \
		rest_framework_dynamicjwt/exceptions.py \
		rest_framework_dynamicjwt/settings.py \
		rest_framework_dynamicjwt/state.py
	$(MAKE) -C docs clean
	$(MAKE) -C docs html
	$(MAKE) -C docs doctest

.PHONY: docs
docs: build-docs
	open docs/_build/html/index.html

.PHONY: linux-docs
linux-docs: build-docs
	xdg-open docs/_build/html/index.html

.PHONY: pushversion
pushversion:
	git push upstream && git push upstream --tags

.PHONY: publish
publish:
	python setup.py sdist bdist_wheel
	twine upload dist/*

.PHONY: dist
dist: clean
	python setup.py sdist bdist_wheel
	ls -l dist
