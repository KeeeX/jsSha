/* eslint-disable @typescript-eslint/no-magic-numbers */
import * as common from "./common.js";
import * as customTypes from "./custom_types.js";
import * as converters from "./converters.js";
import * as primitives32 from "./primitives_32.js";

type Sha256State = Array<number>;

export enum Sha256VariantType {
  sha224 = "SHA-224",
  sha256 = "SHA-256",
}
Object.freeze(Sha256VariantType);

const binaryStringInc = 16;

/**
 * Gets the state values for the specified SHA variant.
 *
 * @param variant - The SHA-256 family variant.
 * @returns The initial state values.
 */
export const getNewState256 = (variant: Sha256VariantType): Sha256State => {
  let retVal;
  if (Sha256VariantType.sha224 === variant) {
    retVal = common.hTrunc.slice();
  } else {
    retVal = common.hFull.slice();
  }
  return retVal;
};

/**
 * Performs a round of SHA-256 hashing over a block. This clobbers `H`.
 *
 * @param block - The binary array representation of the block to hash.
 * @param inputH - The intermediate H values from a previous round.
 * @returns The resulting H values.
 */
export const roundSHA256 = (block: Array<number>, inputH: Sha256State): Sha256State => {
  const W: Array<number> = [];
  let a = inputH[0];
  let b = inputH[1];
  let c = inputH[2];
  let d = inputH[3];
  let e = inputH[4];
  let f = inputH[5];
  let g = inputH[6];
  let h = inputH[7];
  for (let t = 0; t < 64; t += 1) {
    if (t < 16) {
      W[t] = block[t];
    } else {
      W[t] = primitives32.safeAddFour32(
        primitives32.gammaOne32(W[t - 2]),
        W[t - 7],
        primitives32.gammaZero32(W[t - 15]),
        W[t - 16],
      );
    }
    const T1 = primitives32.safeAddFive32(
      h,
      primitives32.sigmaOne32(e),
      primitives32.ch32(e, f, g),
      common.kSha2[t],
      W[t],
    );
    const T2 = primitives32.safeAddTwo32(primitives32.sigmaZero32(a), primitives32.maj32(a, b, c));
    h = g;
    g = f;
    f = e;
    e = primitives32.safeAddTwo32(d, T1);
    d = c;
    c = b;
    b = a;
    a = primitives32.safeAddTwo32(T1, T2);
  }
  inputH[0] = primitives32.safeAddTwo32(a, inputH[0]);
  inputH[1] = primitives32.safeAddTwo32(b, inputH[1]);
  inputH[2] = primitives32.safeAddTwo32(c, inputH[2]);
  inputH[3] = primitives32.safeAddTwo32(d, inputH[3]);
  inputH[4] = primitives32.safeAddTwo32(e, inputH[4]);
  inputH[5] = primitives32.safeAddTwo32(f, inputH[5]);
  inputH[6] = primitives32.safeAddTwo32(g, inputH[6]);
  inputH[7] = primitives32.safeAddTwo32(h, inputH[7]);
  return inputH;
};

/**
 * Finalizes the SHA-256 hash. This clobbers `remainder` and `H`.
 *
 * @param remainder - Any leftover unprocessed packed ints that still need to be processed.
 * @param remainderBinLen - The number of bits in `remainder`.
 * @param processedBinLen - The number of bits already processed.
 * @param inputH - The intermediate H values from a previous round.
 * @param variant - The desired SHA-256 variant.
 * @returns The array of integers representing the SHA-2 hash of message.
 */
const finalizeSHA256 = (
  remainder: Array<number>,
  remainderBinLen: number,
  processedBinLen: number,
  inputH: Sha256State,
  variant: Sha256VariantType,
): Array<number> => {
  /* The 65 addition is a hack but it works.  The correct number is
    actually 72 (64 + 8) but the below math fails if
    remainderBinLen + 72 % 512 = 0. Since remainderBinLen % 8 = 0,
    "shorting" the addition is OK. */
  const offset = (((remainderBinLen + 65) >>> 9) << 4) + 15;
  const totalLen = remainderBinLen + processedBinLen;

  while (remainder.length <= offset) remainder.push(0);
  /* Append '1' at the end of the binary string */
  remainder[remainderBinLen >>> 5] |= 0x80 << (24 - (remainderBinLen % 32));
  /* Append length of binary string in the position such that the new
   * length is correct. JavaScript numbers are limited to 2^53 so it's
   * "safe" to treat the totalLen as a 64-bit integer. */

  remainder[offset] = totalLen & 0xffffffff;
  /* Bitwise operators treat the operand as a 32-bit number so need to
   * use hacky division and round to get access to upper 32-ish bits */
  remainder[offset - 1] = (totalLen / common.TWO_PWR_32) | 0;

  let resultH = inputH;
  /* This will always be at least 1 full chunk */
  for (let i = 0; i < remainder.length; i += binaryStringInc) {
    resultH = roundSHA256(remainder.slice(i, i + binaryStringInc), resultH);
  }

  if (Sha256VariantType.sha224 === variant) {
    return [resultH[0], resultH[1], resultH[2], resultH[3], resultH[4], resultH[5], resultH[6]];
  }
  return resultH;
};

const cloneSha256State = (state: Sha256State): Sha256State => state.slice();
export class JsSha256 extends common.JsSHABase<Sha256State, Sha256VariantType> {
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  protected converterFunc: converters.GenericConverter;
  protected roundFunc: customTypes.RoundFunc<Sha256State> = roundSHA256;
  protected newStateFunc: customTypes.NewStateFunc<Sha256State, Sha256VariantType> = getNewState256;
  protected getMAC: customTypes.GetMacFunc = this._getHMAC;
  protected stateCloneFunc: customTypes.StateCloneFunc<Sha256State> = cloneSha256State;

  public constructor(
    variant: Sha256VariantType,
    inputFormat: customTypes.FormatType.text,
    options?: customTypes.FixedLengthOptionsEncodingType,
  );

  public constructor(
    variant: Sha256VariantType,
    inputFormat: customTypes.FormatNoTextType,
    options?: customTypes.FixedLengthOptionsNoEncodingType,
  );

  public constructor(
    variant: Sha256VariantType,
    inputFormat: customTypes.FormatType,
    options?: customTypes.FixedLengthOptionsEncodingType
    | customTypes.FixedLengthOptionsNoEncodingType,
  ) {
    super(
      {
        bigEndianMod: -1,
        hmacSupported: true,
        intermediateState: getNewState256(variant),
        isVariableLen: false,
        outputBinLen: (variant === Sha256VariantType.sha224) ? 224 : 256,
        variantBlockSize: 512,
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
      this._setHMACKey(common.parseInputOption("hmacKey", resolvedOptions["hmacKey"], this.bigEndianMod));
    }
  }

  protected finalizeFunc: customTypes.FinalizeFunc<Sha256State> = (
    remainder,
    remainderBinLen,
    processedBinLen,
    inputH,
  ) => finalizeSHA256(remainder, remainderBinLen, processedBinLen, inputH, this.shaVariant);
}
