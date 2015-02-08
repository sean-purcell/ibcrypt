DIR=pk
$(DIR)SOURCES:=$(filter-out $(DIR)/bignum_test.c,$(wildcard $(DIR)/*.c))
SOURCES+=$($(DIR)SOURCES)
HEADERS+=$(wildcard $(DIR)/*.h)

