CC = gcc
CFLAGS = -O2 -Wall -Wextra -pthread
LDFLAGS = -lz -lzstd -llz4 -llzma -lssl -lcrypto
# Static link needs libdl for libcrypto on glibc.
LDFLAGS_STATIC = -lz -lzstd -llz4 -llzma -lcrypto -ldl

TARGET = cpu_core_tester
SRC = cpu_core_tester.c

.PHONY: all clean install deps check-deps

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET) kat_dump

# Regenerate golden KAT digests. ONLY run this on a TRUSTED machine,
# then paste the printed table into cpu_core_tester.c.
kat-dump: kat_dump.c $(SRC)
	$(CC) $(CFLAGS) -o kat_dump kat_dump.c $(LDFLAGS)

# Build a self-contained static binary on a TRUSTED machine, copy it to
# the suspect host, and verify the printed SHA256 there before running.
# Do NOT build on the suspect host: the compiler itself would run on
# possibly-failing cores and could emit a corrupted binary.
# NOTE: flags are intentionally generic (-O2, no -march=native) so the
# binary runs on any x86-64, whatever class the Xeon is.
static: $(SRC)
	$(CC) $(CFLAGS) -static -o $(TARGET) $< $(LDFLAGS_STATIC)
	sha256sum $(TARGET)

deps:
	@echo "Installing dependencies (Debian/Ubuntu)..."
	sudo apt-get update && sudo apt-get install -y \
		libz-dev \
		libzstd-dev \
		liblz4-dev \
		liblzma-dev \
		libssl-dev \
		build-essential

check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists zlib 2>/dev/null && echo "  zlib:   found" || echo "  zlib:   MISSING (libz-dev)"
	@pkg-config --exists libzstd 2>/dev/null && echo "  zstd:   found" || echo "  zstd:   MISSING (libzstd-dev)"
	@pkg-config --exists liblz4 2>/dev/null && echo "  lz4:    found" || echo "  lz4:    MISSING (liblz4-dev)"
	@pkg-config --exists liblzma 2>/dev/null && echo "  lzma:   found" || echo "  lzma:   MISSING (liblzma-dev)"
	@pkg-config --exists openssl 2>/dev/null && echo "  ssl:    found" || echo "  ssl:    MISSING (libssl-dev)"

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)
