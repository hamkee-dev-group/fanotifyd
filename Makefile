PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man8

CC      ?= cc
CSTD    ?= -std=c11
CFLAGS  ?= -O2 -g -Wall -Wextra -Wpedantic -Wno-unused-parameter \
           -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
           -fstack-protector-strong -D_GNU_SOURCE
LDFLAGS ?=
LDLIBS  ?=

SRC := \
	src/log.c \
	src/util.c \
	src/buf.c \
	src/path.c \
	src/fan.c \
	src/output.c \
	src/policy.c \
	src/config.c \
	src/daemon.c \
	src/main.c

OBJ := $(SRC:.c=.o)
BIN := fanotifyd

UNIT_SRC := tests/unit_main.c src/buf.c src/util.c src/log.c src/config.c src/output.c src/path.c src/policy.c src/fan.c src/daemon.c
UNIT_BIN := tests/unit
PIVOT_BIN := tests/pivot_writer

.PHONY: all clean install test unit integration check format

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CSTD) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CSTD) $(CFLAGS) -Isrc -c -o $@ $<

$(UNIT_BIN): $(UNIT_SRC)
	$(CC) $(CSTD) $(CFLAGS) -DFANOTIFYD_TESTING -Isrc -o $@ $^

$(PIVOT_BIN): tests/pivot_writer.c
	$(CC) $(CSTD) $(CFLAGS) -o $@ $<

unit: $(UNIT_BIN)
	@echo "[unit] running $(UNIT_BIN)"
	@$(UNIT_BIN)

integration: $(BIN) $(PIVOT_BIN)
	@echo "[integration] running tests/run.sh"
	@sh tests/run.sh

test: unit
	@echo "[test] integration tests require root and are run via 'make integration'"

check: test

clean:
	rm -f $(OBJ) $(BIN) $(UNIT_BIN) $(PIVOT_BIN)

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
