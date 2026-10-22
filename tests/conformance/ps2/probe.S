/* Source-owned Emotion Engine decoding probe. This fixture is never executed.
 * Each instruction has a fixed encoding checked against GNU objdump:
 * MIPS ADDIU, MMI PADDW and PCPYLD, the R5900 three-operand MULT and the
 * VU0 macro-mode VADD.xyzw. */
.set noreorder
.text
.align 3
.globl rea_ps2_probe
.type rea_ps2_probe, @function
.ent rea_ps2_probe
rea_ps2_probe:
  addiu $v0, $zero, 0x1234
  paddw $v1, $a0, $a1
  pcpyld $v1, $v1, $v0
  mult $v0, $a0, $a1
  vadd.xyzw $vf1, $vf2, $vf3
  jr $ra
  nop
.end rea_ps2_probe
.size rea_ps2_probe, .-rea_ps2_probe
