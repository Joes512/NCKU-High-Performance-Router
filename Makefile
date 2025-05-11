CC = gcc
CFLAGS = -O2 -Wall -std=c11

SRCS := $(wildcard *.c)
BINS := $(SRCS:.c=)

all: $(BINS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BINS)
