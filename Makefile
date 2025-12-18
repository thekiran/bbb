CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
BT_CFLAGS := $(shell pkg-config --cflags bluetooth 2>/dev/null)
BT_LIBS := $(shell pkg-config --libs bluetooth 2>/dev/null)

BIN_DIR := bin
SRCS := src/hci_monitor.c src/btsnoop_dump.c
PROGS := $(BIN_DIR)/hci_monitor $(BIN_DIR)/btsnoop_dump

all: $(PROGS)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(BIN_DIR)/hci_monitor: src/hci_monitor.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $(BT_CFLAGS) -o $@ $< $(BT_LIBS)

$(BIN_DIR)/btsnoop_dump: src/btsnoop_dump.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean
