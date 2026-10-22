import type { MipsInspectedReadelfMetadata } from "./mips-checks.mjs";

export type Ps2FixtureVariant = "ps2sdk" | "legacy";

export interface Ps2ProbeInstruction {
  readonly address: string;
  readonly bytes: string;
  readonly gnu_mnemonic: string;
  readonly mnemonic: string;
}

export declare const PS2_PROBE_ENCODINGS: readonly {
  readonly word: string;
  readonly mnemonic: string;
}[];

export declare function parsePs2ReadelfMips(
  text: string,
  variant: Ps2FixtureVariant,
): MipsInspectedReadelfMetadata;

export declare function parsePs2ProbeObjdump(
  text: string,
  probeAddress: string,
): Ps2ProbeInstruction[];
