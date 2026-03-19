SRC=$(wildcard src/*.c)

INCLUDES?=
INCLUDES+=-I src

CFLAGS?=-Wall -std=c99

include lib/.dep/config.mk

CFLAGS+=$(INCLUDES)
CFLAGS+=-D_DEFAULT_SOURCE

OBJ=$(SRC:.c=.o)

BIN=\
	test

LDFLAGS+=-lssl -lcrypto

default: $(BIN)

$(BIN): $(OBJ) $(BIN:=.o)
	$(CC) $(CFLAGS) $(OBJ) $@.o $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -f $(OBJ)
	rm -f $(BIN:=.o)
	rm -f test
