# Makefile for Dolon Port Scanner

CC = gcc
CFLAGS = -Wall -Wextra -pthread
TARGET = dolon_scanner

all: $(TARGET)

$(TARGET): dolon_scanner.c
	$(CC) $(CFLAGS) -o $(TARGET) dolon_scanner.c

clean:
	rm -f $(TARGET) scan.txt

.PHONY: all clean
