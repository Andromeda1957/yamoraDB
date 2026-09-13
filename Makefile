CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -std=c17 -O2 -Wall -Wextra -Wpedantic -Werror
LDLIBS ?= -pthread
SANITIZER_CC ?= clang

BUILD_DIR := build
TARGET := $(BUILD_DIR)/yamldb
SOURCE := src/daemon.c src/snapshot.c src/store.c src/compression.c

.PHONY: all test sanitizer-test clean

all: $(TARGET)

$(TARGET): $(SOURCE) src/snapshot.h src/store.h src/compression.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LDLIBS)

test: $(TARGET)
	python3 -m unittest discover -s tests -p 'test_*.py'

sanitizer-test:
	$(MAKE) clean
	$(MAKE) \
		CC='$(SANITIZER_CC)' \
		CFLAGS='-std=c17 -O1 -g -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-omit-frame-pointer' \
		LDLIBS='-pthread -fsanitize=address,undefined' \
		all
	ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' \
	UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
	python3 -m unittest discover -s tests -p 'test_*.py'

clean:
	if [ -d '$(BUILD_DIR)' ]; then rm -r -- '$(BUILD_DIR)'; fi
