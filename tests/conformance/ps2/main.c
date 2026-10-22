/* Source-owned PS2 Emotion Engine fixture. It is built, never executed. */
#ifndef REA_PS2_GLOBAL
#define REA_PS2_GLOBAL 7
#endif
volatile unsigned int rea_ps2_global = REA_PS2_GLOBAL;
const char rea_ps2_marker[] = "rea-ps2-source-owned-fixture";
unsigned int rea_ps2_probe(void);

__attribute__((noinline)) unsigned int rea_ps2_leaf(unsigned int value) {
  return value * 3u + rea_ps2_global;
}
__attribute__((noinline)) unsigned int rea_ps2_entry(unsigned int selector) {
  unsigned int adjusted = selector > 10u ? selector : selector + 1u;
  return rea_ps2_leaf(adjusted) + rea_ps2_probe();
}
int main(void) {
  return (int)rea_ps2_entry(11u);
}
