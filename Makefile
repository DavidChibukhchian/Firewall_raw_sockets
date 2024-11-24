TARGET = build/firewall

CC = gcc
CFLAGS = -Wall -Iinclude

SRC_files = main.c utils.c rules.c
SRC = $(addprefix source/, $(SRC_files))
OBJ = $(SRC:source/%.c=build/%.o)

all: build $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ)

build/%.o: source/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

clean:
	rm -rf build
	rm -f $(TARGET)

.PHONY: all clean build
