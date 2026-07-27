CC = gcc
CFLAGS = -O2 -Wall -Wextra -pthread
LDFLAGS = -lz -lzstd -lz4 -lssl -lcrypto

TARGET = cpu_core_tester
SRC = cpu_core_tester.c

.PHONY: all clean install deps check-deps

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

deps:
	@echo "Installing dependencies (Debian/Ubuntu)..."
	sudo apt-get update && sudo apt-get install -y \
		libz-dev \
		libzstd-dev \
		liblz4-dev \
		libssl-dev \
		build-essential

check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists zlib 2>/dev/null && echo "  zlib:   found" || echo "  zlib:   MISSING (libz-dev)"
	@pkg-config --exists libzstd 2>/dev/null && echo "  zstd:   found" || echo "  zstd:   MISSING (libzstd-dev)"
	@pkg-config --exists liblz4 2>/dev/null && echo "  lz4:    found" || echo "  lz4:    MISSING (liblz4-dev)"
	@pkg-config --exists openssl 2>/dev/null && echo "  ssl:    found" || echo "  ssl:    MISSING (libssl-dev)"

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)
