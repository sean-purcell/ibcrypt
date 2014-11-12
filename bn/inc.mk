DIR:=bn
$(DIR)SOURCES:=$(wildcard $(DIR)/*.c)
SOURCES+=$($(DIR)SOURCES)

