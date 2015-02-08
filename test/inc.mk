DIR:=test
$(DIR)SOURCES:=$(wildcard $(DIR)/*.c)
TESTSOURCES+=$($(DIR)SOURCES)
HEADERS+=$(wildcard $(DIR)/*.h)

