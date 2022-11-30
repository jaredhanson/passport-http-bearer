include node_modules/make-node/main.mk

MOCHAFLAGS = --require ./test/bootstrap/node
JSDOCFLAGS ?= -c etc/jsdoc.json


# Perform self-tests.
check: test
