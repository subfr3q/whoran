CFLAGS ?= -O2 -g
.PHONY: test clean

whoran: whoran.c report.c report.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c17 -Wall -Wextra -Wpedantic $(LDFLAGS) -o $@ whoran.c report.c

test: whoran
	sh test.sh

clean:
	$(RM) whoran
