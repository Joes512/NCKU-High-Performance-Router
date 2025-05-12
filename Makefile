CC = gcc
CFLAGS = -O2 -Wall -std=c11

SRCS := $(wildcard src/*.c)
BINS := $(SRCS:.c=)

all: $(BINS)

%: src/%.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BINS)
