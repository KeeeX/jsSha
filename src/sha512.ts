/* eslint-disable @typescript-eslint/no-magic-numbers */
import * as common from "./common.js";
import * as customTypes from "./custom_types.js";
import * as converters from "./converters.js";
import * as primitives64 from "./primitives_64.js";

type Sha512State = Array<primitives64.Int64>;

export enum Sha512VariantType {
  sha384 = "SHA-384",
  sha512 = "SHA-512",
}
Object.freeze(Sha512VariantType);

const kSha512 = [
  new primitives64.Int64(common.kSha2[0], 0xd728ae22),
  new primitives64.Int64(common.kSha2[1], 0x23ef65cd),
  new primitives64.Int64(common.kSha2[2], 0xec4d3b2f),
  new primitives64.Int64(common.kSha2[3], 0x8189dbbc),
  new primitives64.Int64(common.kSha2[4], 0xf348b538),
  new primitives64.Int64(common.kSha2[5], 0xb605d019),
  new primitives64.Int64(common.kSha2[6], 0xaf194f9b),
  new primitives64.Int64(common.kSha2[7], 0xda6d8118),
  new primitives64.Int64(common.kSha2[8], 0xa3030242),
  new primitives64.Int64(common.kSha2[9], 0x45706fbe),
  new primitives64.Int64(common.kSha2[10], 0x4ee4b28c),
  new primitives64.Int64(common.kSha2[11], 0xd5ffb4e2),
  new primitives64.Int64(common.kSha2[12], 0xf27b896f),
  new primitives64.Int64(common.kSha2[13], 0x3b1696b1),
  new primitives64.Int64(common.kSha2[14], 0x25c71235),
  new primitives64.Int64(common.kSha2[15], 0xcf692694),
  new primitives64.Int64(common.kSha2[16], 0x9ef14ad2),
  new primitives64.Int64(common.kSha2[17], 0x384f25e3),
  new primitives64.Int64(common.kSha2[18], 0x8b8cd5b5),
  new primitives64.Int64(common.kSha2[19], 0x77ac9c65),
  new primitives64.Int64(common.kSha2[20], 0x592b0275),
  new primitives64.Int64(common.kSha2[21], 0x6ea6e483),
  new primitives64.Int64(common.kSha2[22], 0xbd41fbd4),
  new primitives64.Int64(common.kSha2[23], 0x831153b5),
  new primitives64.Int64(common.kSha2[24], 0xee66dfab),
  new primitives64.Int64(common.kSha2[25], 0x2db43210),
  new primitives64.Int64(common.kSha2[26], 0x98fb213f),
  new primitives64.Int64(common.kSha2[27], 0xbeef0ee4),
  new primitives64.Int64(common.kSha2[28], 0x3da88fc2),
  new primitives64.Int64(common.kSha2[29], 0x930aa725),
  new primitives64.Int64(common.kSha2[30], 0xe003826f),
  new primitives64.Int64(common.kSha2[31], 0x0a0e6e70),
  new primitives64.Int64(common.kSha2[32], 0x46d22ffc),
  new primitives64.Int64(common.kSha2[33], 0x5c26c926),
  new primitives64.Int64(common.kSha2[34], 0x5ac42aed),
  new primitives64.Int64(common.kSha2[35], 0x9d95b3df),
  new primitives64.Int64(common.kSha2[36], 0x8baf63de),
  new primitives64.Int64(common.kSha2[37], 0x3c77b2a8),
  new primitives64.Int64(common.kSha2[38], 0x47edaee6),
  new primitives64.Int64(common.kSha2[39], 0x1482353b),
  new primitives64.Int64(common.kSha2[40], 0x4cf10364),
  new primitives64.Int64(common.kSha2[41], 0xbc423001),
  new primitives64.Int64(common.kSha2[42], 0xd0f89791),
  new primitives64.Int64(common.kSha2[43], 0x0654be30),
  new primitives64.Int64(common.kSha2[44], 0xd6ef5218),
  new primitives64.Int64(common.kSha2[45], 0x5565a910),
  new primitives64.Int64(common.kSha2[46], 0x5771202a),
  new primitives64.Int64(common.kSha2[47], 0x32bbd1b8),
  new primitives64.Int64(common.kSha2[48], 0xb8d2d0c8),
  new primitives64.Int64(common.kSha2[49], 0x5141ab53),
  new primitives64.Int64(common.kSha2[50], 0xdf8eeb99),
  new primitives64.Int64(common.kSha2[51], 0xe19b48a8),
  new primitives64.Int64(common.kSha2[52], 0xc5c95a63),
  new primitives64.Int64(common.kSha2[53], 0xe3418acb),
  new primitives64.Int64(common.kSha2[54], 0x7763e373),
  new primitives64.Int64(common.kSha2[55], 0xd6b2b8a3),
  new primitives64.Int64(common.kSha2[56], 0x5defb2fc),
  new primitives64.Int64(common.kSha2[57], 0x43172f60),
  new primitives64.Int64(common.kSha2[58], 0xa1f0ab72),
  new primitives64.Int64(common.kSha2[59], 0x1a6439ec),
  new primitives64.Int64(common.kSha2[60], 0x23631e28),
  new primitives64.Int64(common.kSha2[61], 0xde82bde9),
  new primitives64.Int64(common.kSha2[62], 0xb2c67915),
  new primitives64.Int64(common.kSha2[63], 0xe372532b),
  new primitives64.Int64(0xca273ece, 0xea26619c),
  new primitives64.Int64(0xd186b8c7, 0x21c0c207),
  new primitives64.Int64(0xeada7dd6, 0xcde0eb1e),
  new primitives64.Int64(0xf57d4f7f, 0xee6ed178),
  new primitives64.Int64(0x06f067aa, 0x72176fba),
  new primitives64.Int64(0x0a637dc5, 0xa2c898a6),
  new primitives64.Int64(0x113f9804, 0xbef90dae),
  new primitives64.Int64(0x1b710b35, 0x131c471b),
  new primitives64.Int64(0x28db77f5, 0x23047d84),
  new primitives64.Int64(0x32caab7b, 0x40c72493),
  new primitives64.Int64(0x3c9ebe0a, 0x15c9bebc),
  new primitives64.Int64(0x431d67c4, 0x9c100d4c),
  new primitives64.Int64(0x4cc5d4be, 0xcb3e42b6),
  new primitives64.Int64(0x597f299c, 0xfc657e2a),
  new primitives64.Int64(0x5fcb6fab, 0x3ad6faec),
  new primitives64.Int64(0x6c44198c, 0x4a475817),
];

/**
 * Gets the state values for the specified SHA variant.
 *
 * @param variant - The SHA-512 family variant.
 * @returns The initial state values.
 */
export const getNewState512 = (variant: Sha512VariantType): Sha512State => {
  if (Sha512VariantType.sha384 === variant) {
    return [
      new primitives64.Int64(0xcbbb9d5d, common.hTrunc[0]),
      new primitives64.Int64(0x0629a292a, common.hTrunc[1]),
      new primitives64.Int64(0x9159015a, common.hTrunc[2]),
      new primitives64.Int64(0x0152fecd8, common.hTrunc[3]),
      new primitives64.Int64(0x67332667, common.hTrunc[4]),
      new primitives64.Int64(0x98eb44a87, common.hTrunc[5]),
      new primitives64.Int64(0xdb0c2e0d, common.hTrunc[6]),
      new primitives64.Int64(0x047b5481d, common.hTrunc[7]),
    ];
  }
  return [
    new primitives64.Int64(common.hFull[0], 0xf3bcc908),
    new primitives64.Int64(common.hFull[1], 0x84caa73b),
    new primitives64.Int64(common.hFull[2], 0xfe94f82b),
    new primitives64.Int64(common.hFull[3], 0x5f1d36f1),
    new primitives64.Int64(common.hFull[4], 0xade682d1),
    new primitives64.Int64(common.hFull[5], 0x2b3e6c1f),
    new primitives64.Int64(common.hFull[6], 0xfb41bd6b),
    new primitives64.Int64(common.hFull[7], 0x137e2179),
  ];
};

/**
 * Performs a round of SHA-512 hashing over a block. This clobbers `H`.
 *
 * @param block - The binary array representation of the block to hash.
 * @param inputH - The intermediate H values from a previous round.
 * @returns The resulting H values.
 */
export const roundSHA512 = (block: Array<number>, inputH: Sha512State): Sha512State => {
  const W: Sha512State = [];
  let a = inputH[0];
  let b = inputH[1];
  let c = inputH[2];
  let d = inputH[3];
  let e = inputH[4];
  let f = inputH[5];
  let g = inputH[6];
  let h = inputH[7];
  for (let t = 0; t < 80; t += 1) {
    if (t < 16) {
      const offset = t * 2;
      W[t] = new primitives64.Int64(block[offset], block[offset + 1]);
    } else {
      W[t] = primitives64.safeAddFour64(
        primitives64.gammaOne64(W[t - 2]),
        W[t - 7],
        primitives64.gammaZero64(W[t - 15]),
        W[t - 16],
      );
    }
    const T1 = primitives64.safeAddFive64(
      h,
      primitives64.sigmaOne64(e),
      primitives64.ch64(e, f, g),
      kSha512[t],
      W[t],
    );
    const T2 = primitives64.safeAddTwo64(primitives64.sigmaZero64(a), primitives64.maj64(a, b, c));
    h = g;
    g = f;
    f = e;
    e = primitives64.safeAddTwo64(d, T1);
    d = c;
    c = b;
    b = a;
    a = primitives64.safeAddTwo64(T1, T2);
  }
  inputH[0] = primitives64.safeAddTwo64(a, inputH[0]);
  inputH[1] = primitives64.safeAddTwo64(b, inputH[1]);
  inputH[2] = primitives64.safeAddTwo64(c, inputH[2]);
  inputH[3] = primitives64.safeAddTwo64(d, inputH[3]);
  inputH[4] = primitives64.safeAddTwo64(e, inputH[4]);
  inputH[5] = primitives64.safeAddTwo64(f, inputH[5]);
  inputH[6] = primitives64.safeAddTwo64(g, inputH[6]);
  inputH[7] = primitives64.safeAddTwo64(h, inputH[7]);
  return inputH;
};

/**
 * Finalizes the SHA-512 hash. This clobbers `remainder` and `H`.
 *
 * @param remainder - Any leftover unprocessed packed ints that still need to be processed.
 * @param remainderBinLen - The number of bits in `remainder`.
 * @param processedBinLen - The number of bits already processed.
 * @param H - The intermediate H values from a previous round.
 * @param variant - The desired SHA-512 variant.
 * @returns The array of integers representing the SHA-512 hash of message.
 */
// eslint-disable-next-line max-lines-per-function
const finalizeSHA512 = (
  remainder: Array<number>,
  remainderBinLen: number,
  processedBinLen: number,
  inputH: Sha512State,
  variant: Sha512VariantType,
): Array<number> => {
  /* The 129 addition is a hack but it works.  The correct number is actually 136 (128 + 8) but the
   * below math fails if remainderBinLen + 136 % 1024 = 0. Since remainderBinLen % 8 = 0, "shorting"
   * the addition is OK. */
  const offset = (((remainderBinLen + 129) >>> 10) << 5) + 31;
  const binaryStringInc = 32;
  const totalLen = remainderBinLen + processedBinLen;
  while (remainder.length <= offset) remainder.push(0);
  /* Append '1' at the end of the binary string */
  remainder[remainderBinLen >>> 5] |= 0x80 << (24 - (remainderBinLen % 32));
  /* Append length of binary string in the position such that the new length is correct. JavaScript
   * numbers are limited to 2^53 so it's "safe" to treat the totalLen as a 64-bit integer. */
  remainder[offset] = totalLen & 0xffffffff;
  /* Bitwise operators treat the operand as a 32-bit number so need to use hacky division and round
   * to get access to upper 32-ish bits */
  remainder[offset - 1] = (totalLen / common.TWO_PWR_32) | 0;
  let resultH = inputH;
  /* This will always be at least 1 full chunk */
  for (let i = 0; i < remainder.length; i += binaryStringInc) {
    resultH = roundSHA512(remainder.slice(i, i + binaryStringInc), resultH);
  }
  if (Sha512VariantType.sha384 === variant) {
    return [
      resultH[0].highOrder,
      resultH[0].lowOrder,
      resultH[1].highOrder,
      resultH[1].lowOrder,
      resultH[2].highOrder,
      resultH[2].lowOrder,
      resultH[3].highOrder,
      resultH[3].lowOrder,
      resultH[4].highOrder,
      resultH[4].lowOrder,
      resultH[5].highOrder,
      resultH[5].lowOrder,
    ];
  }
  return [
    resultH[0].highOrder,
    resultH[0].lowOrder,
    resultH[1].highOrder,
    resultH[1].lowOrder,
    resultH[2].highOrder,
    resultH[2].lowOrder,
    resultH[3].highOrder,
    resultH[3].lowOrder,
    resultH[4].highOrder,
    resultH[4].lowOrder,
    resultH[5].highOrder,
    resultH[5].lowOrder,
    resultH[6].highOrder,
    resultH[6].lowOrder,
    resultH[7].highOrder,
    resultH[7].lowOrder,
  ];
};

const stateCloneFunc = (state: Sha512State): Sha512State => state.slice();

export class JsSha512 extends common.JsSHABase<Sha512State, Sha512VariantType> {
  protected converterFunc: converters.GenericConverter;
  protected roundFunc: customTypes.RoundFunc<Sha512State> = roundSHA512;
  protected stateCloneFunc: customTypes.StateCloneFunc<Sha512State> = stateCloneFunc;
  protected newStateFunc: customTypes.NewStateFunc<Sha512State, Sha512VariantType> = getNewState512;
  protected getMAC: customTypes.GetMacFunc = this._getHMAC;

  public constructor(
    variant: Sha512VariantType,
    inputFormat: customTypes.FormatType.text,
    options?: customTypes.FixedLengthOptionsEncodingType,
  );

  public constructor(
    variant: Sha512VariantType,
    inputFormat: customTypes.FormatNoTextType,
    options?: customTypes.FixedLengthOptionsNoEncodingType,
  );

  public constructor(
    variant: Sha512VariantType,
    inputFormat: customTypes.FormatType,
    options?: customTypes.FixedLengthOptionsEncodingType
    | customTypes.FixedLengthOptionsNoEncodingType,
  ) {
    super(
      {
        bigEndianMod: -1,
        hmacSupported: true,
        intermediateState: getNewState512(variant),
        isVariableLen: false,
        outputBinLen: Sha512VariantType.sha384 === variant ? 384 : 512,
        variantBlockSize: 1024,
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
    if ("hmacKey" in resolvedOptions && resolvedOptions.hmacKey) {
      this._setHMACKey(
        common.parseInputOption("hmacKey", resolvedOptions.hmacKey, this.bigEndianMod),
      );
    }
  }

  protected finalizeFunc = (
    remainder: Array<number>,
    remainderBinLen: number,
    processedBinLen: number,
    inputH: Sha512State,
  ): Array<number> => finalizeSHA512(
    remainder,
    remainderBinLen,
    processedBinLen,
    inputH,
    this.shaVariant,
  );
}
