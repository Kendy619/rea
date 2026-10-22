/* Legacy-SDK declaration shape: EABI64 header, no ABI flags record. */
ENTRY(rea_ps2_start)
SECTIONS {
  . = 0x00100000;
  .text : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.* .sdata .sdata.*) }
  .bss : { *(.bss .bss.* .sbss .sbss.* COMMON) }
  /DISCARD/ : { *(.MIPS.abiflags) *(.reginfo) *(.gnu.attributes) *(.pdr) *(.comment) *(.note.*) }
}
