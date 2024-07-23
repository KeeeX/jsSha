/* eslint-disable @typescript-eslint/no-magic-numbers */
import * as common from "./common.js";
import * as customTypes from "./custom_types.js";
import * as converters from "./converters.js";
import * as primitives32 from "./primitives_32.js";

type Sha1State = Array<number>;

export enum Sha1VariantType {
  sha1 = "SHA-1",
}
Object.freeze(Sha1VariantType);

/**
 * Gets the state values for the specified SHA variant.
 *
 * @returns The initial state values.
 */
export const getNewState = (): Sha1State => [
  0x67452301,
  0xefcdab89,
  0x98badcfe,
  0x10325476,
  0xc3d2e1f0,
];

/**
 * Performs a round of SHA-1 hashing over a 512-byte block.  This clobbers `H`.
 *
 * @param block - The binary array representation of the block to hash.
 * @param h - The intermediate H values from a previous round.
 * @returns The resulting H values.
 */
// eslint-disable-next-line max-lines-per-function
export const roundSHA1 = (block: Array<number>, h: Sha1State): Sha1State => {
  const W: Sha1State = [];
  let a = h[0];
  let b = h[1];
  let c = h[2];
  let d = h[3];
  let e = h[4];
  for (let t = 0; t < 80; t += 1) {
    if (t < 16) {
      W[t] = block[t];
    } else {
      W[t] = primitives32.rotl32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }
    let T;
    if (t < 20) {
      T = primitives32.safeAddFive32(
        primitives32.rotl32(a, 5),
        primitives32.ch32(b, c, d),
        e,
        0x5a827999,
        W[t],
      );
    } else if (t < 40) {
      T = primitives32.safeAddFive32(
        primitives32.rotl32(a, 5),
        primitives32.parity32(b, c, d),
        e,
        0x6ed9eba1,
        W[t],
      );
    } else if (t < 60) {
      T = primitives32.safeAddFive32(
        primitives32.rotl32(a, 5),
        primitives32.maj32(b, c, d),
        e,
        0x8f1bbcdc,
        W[t],
      );
    } else {
      T = primitives32.safeAddFive32(
        primitives32.rotl32(a, 5),
        primitives32.parity32(b, c, d),
        e,
        0xca62c1d6,
        W[t],
      );
    }
    e = d;
    d = c;
    c = primitives32.rotl32(b, 30);
    b = a;
    a = T;
  }
  h[0] = primitives32.safeAddTwo32(a, h[0]);
  h[1] = primitives32.safeAddTwo32(b, h[1]);
  h[2] = primitives32.safeAddTwo32(c, h[2]);
  h[3] = primitives32.safeAddTwo32(d, h[3]);
  h[4] = primitives32.safeAddTwo32(e, h[4]);
  return h;
};

/**
 * Finalizes the SHA-1 hash.  This clobbers `remainder` and `H`.
 *
 * @param remainder - Any leftover unprocessed packed ints that still need to be processed.
 * @param remainderBinLen - The number of bits in `remainder`.
 * @param processedBinLen - The number of bits already processed.
 * @param h - The intermediate H values from a previous round.
 * @returns The array of integers representing the SHA-1 hash of message.
 */
export const finalizeSHA1 = (
  remainder: Array<number>,
  remainderBinLen: number,
  processedBinLen: number,
  h: Sha1State,
): Array<number> => {
  /* The 65 addition is a hack but it works.  The correct number is
   * actually 72 (64 + 8) but the below math fails if
   * remainderBinLen + 72 % 512 = 0. Since remainderBinLen % 8 = 0,
   * "shorting" the addition is OK.
   */
  const offset = (((remainderBinLen + 65) >>> 9) << 4) + 15;
  const totalLen = remainderBinLen + processedBinLen;

  while (remainder.length <= offset) remainder.push(0);

  /* Append '1' at the end of the binary string */
  remainder[remainderBinLen >>> 5] |= 0x80 << (24 - (remainderBinLen % 32));

  /* Append length of binary string in the position such that the new
   * length is a multiple of 512.  Logic does not work for even multiples
   * of 512 but there can never be even multiples of 512. JavaScript
   * numbers are limited to 2^53 so it's "safe" to treat the totalLen as
   * a 64-bit integer. */
  remainder[offset] = totalLen & 0xffffffff;

  /* Bitwise operators treat the operand as a 32-bit number so need to
   * use hacky division and round to get access to upper 32-ish bits */
  remainder[offset - 1] = (totalLen / common.TWO_PWR_32) | 0;

  let resultH = h;
  /* This will always be at least 1 full chunk */
  for (let i = 0; i < remainder.length; i += 16) {
    resultH = roundSHA1(remainder.slice(i, i + 16), resultH);
  }
  return resultH;
};

export class JsSha1 extends common.JsSHABase<Sha1State, Sha1VariantType> {
  protected converterFunc: converters.GenericConverter;
  protected roundFunc: customTypes.RoundFunc<Sha1State> = roundSHA1;
  protected finalizeFunc: customTypes.FinalizeFunc<Sha1State> = finalizeSHA1;
  protected newStateFunc: customTypes.NewStateFunc<Sha1State, Sha1VariantType> = getNewState;
  protected getMAC: customTypes.GetMacFunc = this._getHMAC;

  public constructor(
    variant: Sha1VariantType.sha1,
    inputFormat: customTypes.FormatType.text,
    options?: customTypes.FixedLengthOptionsEncodingType,
  );

  public constructor(
    variant: Sha1VariantType.sha1,
    inputFormat: customTypes.FormatNoTextType,
    options?: customTypes.FixedLengthOptionsNoEncodingType,
  );

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public constructor(
    variant: Sha1VariantType,
    inputFormat: customTypes.FormatType,
    options?: customTypes.FixedLengthOptionsEncodingType
    | customTypes.FixedLengthOptionsNoEncodingType,
  ) {
    super(
      {
        intermediateState: getNewState(),
        variantBlockSize: 512,
        bigEndianMod: -1,
        outputBinLen: 160,
        isVariableLen: false,
        hmacSupported: true,
      },
      variant,
      inputFormat as customTypes.FormatNoTextType,
      options,
    );

    this.converterFunc = converters.getStrConverter(
      this.inputFormat,
      this.utfType,
      this.bigEndianMod,
    );

    const resolvedOptions = options ?? {};
    if ("hmacKey" in resolvedOptions) {
      this._setHMACKey(common.parseInputOption(
        "hmacKey",
        resolvedOptions["hmacKey"],
        this.bigEndianMod,
      ));
    }
  }

  // eslint-disable-next-line class-methods-use-this
  protected stateCloneFunc: customTypes.StateCloneFunc<Sha1State> = state => state.slice();
}
