DIR:=bn
$(DIR)SOURCES:=$(filter-out $(DIR)/bignum_test.c,$(wildcard $(DIR)/*.c))
SOURCES+=$($(DIR)SOURCES)
HEADERS+=$(DIR)/bignum.h # leave out bignum_util.h

