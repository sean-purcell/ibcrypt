DIR:=misc
$(DIR)SOURCES:=$(wildcard $(DIR)/*.c)
SOURCES+=$($(DIR)SOURCES)

