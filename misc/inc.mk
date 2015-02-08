DIR:=misc
$(DIR)SOURCES:=$(wildcard $(DIR)/*.c)
SOURCES+=$($(DIR)SOURCES)
HEADERS+=$(wildcard $(DIR)/*.h)

