DIR:=test
$(DIR)SOURCES:=$(wildcard $(DIR)/*.c)
SOURCES+=$($(DIR)SOURCES)

