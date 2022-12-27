CC = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
OBJDUMP = arm-none-eabi-objdump

CFLAGS = -c -Os -fPIC -Iinclude \
         -g -gdwarf -Wno-unused-but-set-variable -fno-inline -fno-omit-frame-pointer \
         -fno-ipa-cp-clone -fno-ipa-cp -fno-common -fno-builtin -ffreestanding -fno-stack-protector -Wall -Wno-format-security \
         -Wno-format-nonliteral -Wno-return-local-addr -Wno-int-to-pointer-cast -march=armv7-a \
		 -DMCUBOOT_FIH_PROFILE_ON -DMCUBOOT_FIH_PROFILE_HIGH -DFAULT_INJECTION_TEST

CFLAGS_LD = -N -Wl,--build-id=none -fPIC -fPIE -g -gdwarf -Os -Wno-unused-but-set-variable -Wno-return-local-addr -fno-inline -fno-ipa-cp-clone \
            -fno-ipa-cp -nostartfiles -nodefaultlibs -march=armv7-a

DEPS = include/common.h
OBJ = bin/aarch32/obj/entry.o $(patsubst src/%.c,bin/aarch32/obj/%.o,$(wildcard src/*.c))

all: bin/aarch32/bl1.bin

bin/aarch32/obj/entry.o: src/aarch32/entry.S
	@mkdir -p bin/aarch32/obj
	$(CC) -c -o $@ src/aarch32/entry.S $(CFLAGS)

bin/aarch32/obj/%.o: src/%.c $(DEPS)
	@mkdir -p bin/aarch32/obj
	$(CC) -c -o $@ $< $(CFLAGS) -Wa,-adhlns="$@.lst"

bin/aarch32/bl1.elf: $(OBJ) src/aarch32/bl1.lds
	$(CC) -o $@ -Tsrc/aarch32/bl1.lds $(CFLAGS_LD) $(OBJ) -lgcc
	arm-none-eabi-objdump -d $@ > bin/aarch32/bl1.lst

bin/aarch32/bl1.bin: bin/aarch32/bl1.elf
	$(OBJCOPY) -O binary $< $@

.PHONY: clean
clean:
	rm -rf bin
