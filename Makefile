CC=gcc
CFLAGS=-Wall -Wextra -std=gnu17 -Iinclude
LDFLAGS=-lpcap

SRCS=src/main.c src/capture.c src/protocol.c src/stats.c src/reassembly.c
OBJS=$(SRCS:.c=.o)
TARGET=sniffer

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)