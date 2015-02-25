DIR=pk
$(DIR)SOURCES:=$(filter-out $(DIR)/rsa_util_test.c $(DIR)/rsa_test.c,$(wildcard $(DIR)/*.c))
SOURCES+=$($(DIR)SOURCES)
HEADERS+=$(wildcard $(DIR)/*.h)

