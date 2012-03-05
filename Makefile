NODE = node
TEST = ./node_modules/.bin/vows
TESTS ?= test/*-test.js

test:
	@NODE_ENV=test NODE_PATH=lib $(TEST) $(TEST_FLAGS) $(TESTS)

docs: docs/api.html

docs/api.html: lib/passport-http-bearer/*.js
	dox \
		--title Passport-HTTP-Bearer \
		--desc "HTTP Bearer authentication strategy for Passport" \
		$(shell find lib/passport-http-bearer/* -type f) > $@

docclean:
	rm -f docs/*.{1,html}

.PHONY: test docs docclean
