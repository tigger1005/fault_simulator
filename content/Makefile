CC = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
OBJDUMP = arm-none-eabi-objdump
TARGET = armv8-m.main

CFLAGS = -c -O3  -Iinclude \
         -g -gdwarf -Wno-unused-but-set-variable -fno-inline -fno-omit-frame-pointer \
         -fno-ipa-cp-clone -fno-ipa-cp -fno-common -fno-builtin -ffreestanding -fno-stack-protector -Wall -Wno-format-security \
         -Wno-format-nonliteral -Wno-return-local-addr -Wno-int-to-pointer-cast -march=$(TARGET) \
		 -DMCUBOOT_FIH_PROFILE_ON -DMCUBOOT_FIH_PROFILE_HIGH -DFAULT_INJECTION_TEST

CFLAGS_LD = -N -Wl,--build-id=none -g -gdwarf -Os -Wno-unused-but-set-variable -Wno-return-local-addr -fno-inline -fno-ipa-cp-clone \
            -fno-ipa-cp -nostartfiles -nodefaultlibs -march=$(TARGET)

DEPS = include/common.h
OBJ = bin/aarch32/obj/entry.o $(patsubst src/%.c,bin/aarch32/obj/%.o,$(wildcard src/*.c))

all: bin/aarch32/victim.bin

bin/aarch32/obj/entry.o: src/aarch32/entry.S
# Target OS detection
ifeq ($(OS),Windows_NT)
	@if not exist "bin/aarch32/obj" @mkdir "bin/aarch32/obj"
else # ifeq ($(OS),linux)
	@mkdir -p bin/aarch32/obj
endif

	$(CC) -c -o $@ src/aarch32/entry.S $(CFLAGS)

bin/aarch32/obj/%.o: src/%.c $(DEPS)
# Target OS detection
ifeq ($(OS),Windows_NT)
	@if not exist "bin/aarch32/obj" @mkdir "bin/aarch32/obj"
else ifeq ($(OS),linux)
	@mkdir -p bin/aarch32/obj
endif

	$(CC) -c -o $@ $< $(CFLAGS) -Wa,-adhlns="$@.lst"

bin/aarch32/victim.elf: $(OBJ) src/aarch32/victim.lds
	$(CC) -o $@ -Tsrc/aarch32/victim.lds $(CFLAGS_LD) $(OBJ) -lgcc
	$(OBJDUMP) -S -d $@ > bin/aarch32/victim.lst

bin/aarch32/victim.bin: bin/aarch32/victim.elf
	$(OBJCOPY) -O binary $< $@

.PHONY: clean
clean:
ifeq ($(OS),Windows_NT)
	@if exist "bin" @rmdir "bin" /s /q
else # ifeq ($(OS),linux)
	rm -rf bin
endif
