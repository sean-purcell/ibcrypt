DIR:=cipher
$(DIR)SOURCES:=$(wildcard $(DIR)/*.c)
SOURCES+=$($(DIR)SOURCES)

