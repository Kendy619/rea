# Source-owned PS2 fixtures. Built with ps2dev/PS2SDK, never executed.
#   rea_ps2_fixture.elf: standard PS2SDK n32 executable (crt0, linkfile, libc).
#   rea_ps2_legacy.elf:  freestanding EABI64 control without an ABI flags record,
#                        the header shape legacy SDK executables declare.
EE_BIN = rea_ps2_fixture.elf
EE_OBJS = main.o probe.o
REA_PS2_GLOBAL ?= 7
EE_OPTFLAGS = -O0
EE_DBGINFOFLAGS = -g
EE_CFLAGS = -fno-inline -fno-builtin -ffile-prefix-map=$(CURDIR)=. -DREA_PS2_GLOBAL=$(REA_PS2_GLOBAL)
# PS2SDK libraries are LTO objects; keep the link-time build directory out too.
EE_LDFLAGS = -ffile-prefix-map=$(CURDIR)=.
LEGACY_FLAGS = -mabi=eabi -mno-abicalls -G0 -O0 -ffreestanding -fno-inline -fno-builtin

all: $(EE_BIN) rea_ps2_legacy.elf

rea_ps2_legacy.elf: main.c start.c probe.S legacy.ld
	$(EE_CC) $(LEGACY_FLAGS) -DREA_PS2_GLOBAL=$(REA_PS2_GLOBAL) -c main.c -o legacy-main.o
	$(EE_CC) $(LEGACY_FLAGS) -c start.c -o legacy-start.o
	$(EE_CC) -mabi=eabi -mno-abicalls -c probe.S -o legacy-probe.o
	$(EE_LD) -m elf32lr5900 -T legacy.ld -o $@ legacy-start.o legacy-main.o legacy-probe.o

include $(PS2SDK)/samples/Makefile.pref
include $(PS2SDK)/samples/Makefile.eeglobal
