CC ?= gcc
CFLAGS ?= -shared -fPIC -O3

# Detect OS for dynamic library extension
ifeq ($(OS),Windows_NT)
    TARGET_EXT = dll
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        TARGET_EXT = dylib
    else
        TARGET_EXT = so
    endif
endif

TARGET = ../libdpi.$(TARGET_EXT)

.PHONY: all clean

all: $(TARGET)

$(TARGET): dpi.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f ../libdpi.so ../libdpi.dll ../libdpi.dylib
