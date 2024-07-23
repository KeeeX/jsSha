/* eslint-disable @typescript-eslint/no-magic-numbers */
import * as common from "./common.js";
import * as customTypes from "./custom_types.js";
import * as converters from "./converters.js";
import * as primitives64 from "./primitives_64.js";

type Sha3State = Array<Array<primitives64.Int64>>;

export enum Sha3VariantType {
  sha3224 = "SHA3-224",
  sha3256 = "SHA3-256",
  sha3384 = "SHA3-384",
  sha3512 = "SHA3-512",
  shake128 = "SHAKE128",
  shake256 = "SHAKE256",
  cshake128 = "CSHAKE128",
  cshake256 = "CSHAKE256",
  kmac128 = "KMAC128",
  kmac256 = "KMAC256",
}
Object.freeze(Sha3VariantType);

export type Sha3FixedLengthVariantType =
| Sha3VariantType.sha3224
| Sha3VariantType.sha3256
| Sha3VariantType.sha3384
| Sha3VariantType.sha3512
| Sha3VariantType.shake128
| Sha3VariantType.shake256;

export type Sha3VariableLengthVariantType =
| Sha3VariantType.shake128
| Sha3VariantType.shake256
| Sha3VariantType.cshake128
| Sha3VariantType.cshake256
| Sha3VariantType.kmac128
| Sha3VariantType.kmac256;

const rcSha3 = [
  new primitives64.Int64(0x00000000, 0x00000001),
  new primitives64.Int64(0x00000000, 0x00008082),
  new primitives64.Int64(0x80000000, 0x0000808a),
  new primitives64.Int64(0x80000000, 0x80008000),
  new primitives64.Int64(0x00000000, 0x0000808b),
  new primitives64.Int64(0x00000000, 0x80000001),
  new primitives64.Int64(0x80000000, 0x80008081),
  new primitives64.Int64(0x80000000, 0x00008009),
  new primitives64.Int64(0x00000000, 0x0000008a),
  new primitives64.Int64(0x00000000, 0x00000088),
  new primitives64.Int64(0x00000000, 0x80008009),
  new primitives64.Int64(0x00000000, 0x8000000a),
  new primitives64.Int64(0x00000000, 0x8000808b),
  new primitives64.Int64(0x80000000, 0x0000008b),
  new primitives64.Int64(0x80000000, 0x00008089),
  new primitives64.Int64(0x80000000, 0x00008003),
  new primitives64.Int64(0x80000000, 0x00008002),
  new primitives64.Int64(0x80000000, 0x00000080),
  new primitives64.Int64(0x00000000, 0x0000800a),
  new primitives64.Int64(0x80000000, 0x8000000a),
  new primitives64.Int64(0x80000000, 0x80008081),
  new primitives64.Int64(0x80000000, 0x00008080),
  new primitives64.Int64(0x00000000, 0x80000001),
  new primitives64.Int64(0x80000000, 0x80008008),
];

const rSha3 = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

/**
 * Gets the state values for the specified SHA-3 variant.
 *
 * @returns The initial state values.
 */
export const getNewState = (): Sha3State => {
  const retVal = [];
  for (let i = 0; i < 5; i += 1) {
    retVal[i] = [
      new primitives64.Int64(0, 0),
      new primitives64.Int64(0, 0),
      new primitives64.Int64(0, 0),
      new primitives64.Int64(0, 0),
      new primitives64.Int64(0, 0),
    ];
  }
  return retVal;
};

/**
 * Returns a clone of the given SHA3 state.
 *
 * @param state - The state to be cloned.
 * @returns The cloned state.
 */
export const cloneSHA3State = (state: Sha3State): Sha3State => state.map(c => c.slice());

/**
 * Performs a round of SHA-3 hashing over a block. This clobbers `state`.
 *
 * @param block - The binary array representation of the block to hash.
 * @param state - Hash state from a previous round.
 * @returns The resulting state value.
 */
export const roundSHA3 = (block: Array<number> | null, state: Sha3State): Sha3State => {
  const C = [];
  const D = [];
  if (null !== block) {
    for (let x = 0; x < block.length; x += 2) {
      state[(x >>> 1) % 5][((x >>> 1) / 5) | 0] = primitives64.xorTwo64(
        state[(x >>> 1) % 5][((x >>> 1) / 5) | 0],
        new primitives64.Int64(block[x + 1], block[x]),
      );
    }
  }
  for (let round = 0; round < 24; round += 1) {
    /* Any SHA-3 variant name will do here */
    const B = getNewState();
    /* Perform theta step */
    for (let x = 0; x < 5; x += 1) {
      C[x] = primitives64.xorFive64(
        state[x][0],
        state[x][1],
        state[x][2],
        state[x][3],
        state[x][4],
      );
    }
    for (let x = 0; x < 5; x += 1) {
      D[x] = primitives64.xorTwo64(C[(x + 4) % 5], primitives64.rotl64(C[(x + 1) % 5], 1));
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[x][y] = primitives64.xorTwo64(state[x][y], D[x]);
      }
    }
    /* Perform combined ro and pi steps */
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        B[y][((2 * x) + (3 * y)) % 5] = primitives64.rotl64(state[x][y], rSha3[x][y]);
      }
    }
    /* Perform chi step */
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        state[x][y] = primitives64.xorTwo64(
          B[x][y],
          new primitives64.Int64(
            ~B[(x + 1) % 5][y].highOrder & B[(x + 2) % 5][y].highOrder,
            ~B[(x + 1) % 5][y].lowOrder & B[(x + 2) % 5][y].lowOrder,
          ),
        );
      }
    }
    /* Perform iota step */
    state[0][0] = primitives64.xorTwo64(state[0][0], rcSha3[round]);
  }
  return state;
};

/**
 * Finalizes the SHA-3 hash. This clobbers `remainder` and `state`.
 *
 * @param remainderLocal - Any leftover unprocessed packed ints that still need to be processed.
 * @param remainderBinLenLocal - The number of bits in `remainder`.
 * @param _processedBinLen - Unused for this family.
 * @param stateLocal - The state from a previous round.
 * @param blockSize - The block size/rate of the variant in bits
 * @param delimiter - The delimiter value for the variant
 * @param outputLen - The output length for the variant in bits
 * @returns The array of integers representing the SHA-3 hash of message.
 */
const finalizeSHA3 = (
  remainder: Array<number>,
  remainderBinLen: number,
  _processedBinLen: number,
  state: Sha3State,
  blockSize: number,
  delimiter: number,
  outputLen: number,
): Array<number> => {
  let stateOffset = 0;
  let remainderLocal = remainder;
  let stateLocal = state;
  let remainderBinLenLocal = remainderBinLen;
  let i;
  const retVal = [];
  const binaryStringInc = blockSize >>> 5;
  const remainderIntLen = remainderBinLenLocal >>> 5;

  /* Process as many blocks as possible, some may be here for multiple rounds with SHAKE */
  for (i = 0; i < remainderIntLen && remainderBinLenLocal >= blockSize; i += binaryStringInc) {
    stateLocal = roundSHA3(remainderLocal.slice(i, i + binaryStringInc), stateLocal);
    remainderBinLenLocal -= blockSize;
  }
  remainderLocal = remainderLocal.slice(i);
  remainderBinLenLocal %= blockSize;
  /* Pad out the remainder to a full block */
  while (remainderLocal.length < binaryStringInc) remainderLocal.push(0);

  /* Find the next "empty" byte for the 0x80 and append it via an xor */
  i = remainderBinLenLocal >>> 3;
  remainderLocal[i >> 2] ^= delimiter << (8 * (i % 4));

  remainderLocal[binaryStringInc - 1] ^= 0x80000000;
  stateLocal = roundSHA3(remainderLocal, stateLocal);

  while (retVal.length * 32 < outputLen) {
    const temp = stateLocal[stateOffset % 5][(stateOffset / 5) | 0];
    retVal.push(temp.lowOrder);
    if (retVal.length * 32 >= outputLen) break;
    retVal.push(temp.highOrder);
    stateOffset += 1;

    if (0 === (stateOffset * 64) % blockSize) {
      roundSHA3(null, stateLocal);
      stateOffset = 0;
    }
  }
  return retVal;
};

/**
 * Performs NIST left_encode function returned with no extra garbage bits. `x` is limited to
 * \<= 9007199254740991.
 *
 * @param x - 32-bit number to to encode.
 * @returns The NIST specified output of the function.
 */
export const leftEncode = (x: number): customTypes.PackedValue => {
  let numEncodedBytes = 0;
  /* JavaScript numbers max out at 0x1FFFFFFFFFFFFF (7 bytes) so this will return a maximum of
   * 7 + 1 = 8 bytes
   */
  const retVal = [0, 0];
  const x64 = [x & 0xffffffff, (x / common.TWO_PWR_32) & 0x1fffff];

  for (let byteOffset = 6; byteOffset >= 0; byteOffset--) {
    /* This will surprisingly work for large shifts because JavaScript masks the shift amount by
     * 0x1F
     */
    const byte = (x64[byteOffset >> 2] >>> (8 * byteOffset)) & 0xff;

    /* Starting from the most significant byte of a 64-bit number, start recording the first non-0
     * byte and then every byte thereafter
     */
    if (byte !== 0 || numEncodedBytes !== 0) {
      retVal[(numEncodedBytes + 1) >> 2] |= byte << ((numEncodedBytes + 1) * 8);
      numEncodedBytes += 1;
    }
  }
  numEncodedBytes = numEncodedBytes === 0 ? 1 : numEncodedBytes;
  retVal[0] |= numEncodedBytes;

  return {value: numEncodedBytes + 1 > 4 ? retVal : [retVal[0]], binLen: 8 + (numEncodedBytes * 8)};
};

/**
 * Performs NIST right_encode function returned with no extra garbage bits. `x` is limited to
 * \<= 9007199254740991.
 *
 * @param x -  32-bit number to to encode.
 * @returns The NIST specified output of the function.
 */
export const rightEncode = (x: number): customTypes.PackedValue => {
  let numEncodedBytes = 0;
  /* JavaScript numbers max out at 0x1FFFFFFFFFFFFF (7 bytes) so this will return a maximum of
   * 7 + 1 = 8 bytes
   */
  const retVal = [0, 0];
  const x64 = [x & 0xffffffff, (x / common.TWO_PWR_32) & 0x1fffff];

  for (let byteOffset = 6; byteOffset >= 0; byteOffset--) {
    /* This will surprisingly work for large shifts because JavaScript masks the shift amount by
     * 0x1F
     */
    const byte = (x64[byteOffset >> 2] >>> (8 * byteOffset)) & 0xff;
    /* Starting from the most significant byte of a 64-bit number, start recording the first non-0
     * byte and then every byte thereafter
     */
    if (byte !== 0 || numEncodedBytes !== 0) {
      retVal[numEncodedBytes >> 2] |= byte << (numEncodedBytes * 8);
      numEncodedBytes += 1;
    }
  }
  numEncodedBytes = numEncodedBytes === 0 ? 1 : numEncodedBytes;
  retVal[numEncodedBytes >> 2] |= numEncodedBytes << (numEncodedBytes * 8);

  return {value: numEncodedBytes + 1 > 4 ? retVal : [retVal[0]], binLen: 8 + (numEncodedBytes * 8)};
};

/**
 * Performs NIST encode_string function.
 *
 * @param input - Packed array of integers.
 * @returns NIST encode_string output.
 */
export const encodeString = (
  input: customTypes.PackedValue,
): customTypes.PackedValue => common.packedLEConcat(
  leftEncode(input.binLen),
  input,
);

/**
 * Performs NIST byte_pad function.
 *
 * @param packed - Packed array of integers.
 * @param outputByteLen - Desired length of the output in bytes, assumed to be a multiple of 4.
 * @returns NIST byte_pad output.
 */
export const bytePad = (packed: customTypes.PackedValue, outputByteLen: number): Array<number> => {
  let encodedLen = leftEncode(outputByteLen);
  encodedLen = common.packedLEConcat(encodedLen, packed);
  const outputIntLen = outputByteLen >>> 2;
  const intsToAppend = (outputIntLen - (encodedLen.value.length % outputIntLen)) % outputIntLen;
  for (let i = 0; i < intsToAppend; i++) encodedLen.value.push(0);
  return encodedLen.value;
};

/**
 * Parses/validate constructor options for a CSHAKE variant
 *
 * @param options - Option given to constructor
 */
export const resolveCSHAKEOptions = (
  options?: customTypes.CSHAKEOptionsNoEncodingType,
): customTypes.ResolvedCSHAKEOptionsNoEncodingType => {
  const resolvedOptions = options ?? {};
  return {
    funcName: common.parseInputOption("funcName", resolvedOptions.funcName, 1, {value: [], binLen: 0}),
    customization: common.parseInputOption(
      "Customization",
      resolvedOptions.customization,
      1,
      {value: [], binLen: 0},
    ),
  };
};

/**
 * Parses/validate constructor options for a KMAC variant
 *
 * @param options - Option given to constructor
 */
export const resolveKMACOptions = (
  options?: customTypes.KMACOptionsNoEncodingType,
): customTypes.ResolvedKMACOptionsNoEncodingType => {
  const resolvedOptions: Record<string, customTypes.GenericInputType> = {...options};
  return {
    kmacKey: common.parseInputOption("kmacKey", resolvedOptions.kmacKey, 1),
    /* This is little-endian packed "KMAC" */
    funcName: {value: [0x43414d4b], binLen: 32},
    customization: common.parseInputOption(
      "Customization",
      resolvedOptions.customization,
      1,
      {value: [], binLen: 0},
    ),
  };
};

// eslint-disable-next-line max-lines-per-function
const getVariantCtorState = (
  variant: Sha3VariantType,
): Omit<common.CtorState<Sha3State>, "bigEndianMod" | "intermediateState"> => {
  switch (variant) {
  case Sha3VariantType.sha3224:
    return {
      hmacSupported: true,
      variantBlockSize: 1152,
      isVariableLen: false,
      outputBinLen: 224,
    };
  case Sha3VariantType.sha3256:
    return {
      hmacSupported: true,
      variantBlockSize: 1088,
      isVariableLen: false,
      outputBinLen: 256,
    };
  case Sha3VariantType.sha3384:
    return {
      hmacSupported: true,
      variantBlockSize: 832,
      isVariableLen: false,
      outputBinLen: 384,
    };
  case Sha3VariantType.sha3512:
    return {
      hmacSupported: true,
      variantBlockSize: 576,
      isVariableLen: false,
      outputBinLen: 512,
    };
  case Sha3VariantType.shake128:
    return {
      hmacSupported: false,
      variantBlockSize: 1344,
      isVariableLen: true,
      outputBinLen: -1,
    };
  case Sha3VariantType.shake256:
    return {
      hmacSupported: false,
      variantBlockSize: 1088,
      isVariableLen: true,
      outputBinLen: -1,
    };
  case Sha3VariantType.kmac128:
    return {
      hmacSupported: false,
      variantBlockSize: 1344,
      isVariableLen: true,
      outputBinLen: -1,
    };
  case Sha3VariantType.kmac256:
    return {
      hmacSupported: false,
      variantBlockSize: 1088,
      isVariableLen: true,
      outputBinLen: -1,
    };
  case Sha3VariantType.cshake128:
    return {
      hmacSupported: false,
      variantBlockSize: 1344,
      isVariableLen: true,
      outputBinLen: -1,
    };
  case Sha3VariantType.cshake256:
    return {
      hmacSupported: false,
      variantBlockSize: 1088,
      isVariableLen: true,
      outputBinLen: -1,
    };
  }
};

export class JsSHA3 extends common.JsSHABase<Sha3State, Sha3VariantType> {
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  protected converterFunc: converters.GenericConverter;
  protected roundFunc: customTypes.RoundFunc<Sha3State> = roundSHA3;
  protected finalizeFunc: customTypes.FinalizeFunc<Sha3State>;
  protected stateCloneFunc: customTypes.StateCloneFunc<Sha3State> = cloneSHA3State;
  protected newStateFunc: customTypes.NewStateFunc<Sha3State, Sha3VariantType> = getNewState;
  protected getMAC: customTypes.GetMacFunc | null;

  public constructor(
    variant: Sha3FixedLengthVariantType,
    inputFormat: customTypes.FormatType.text,
    options?: customTypes.FixedLengthOptionsEncodingType,
  );

  public constructor(
    variant: Sha3FixedLengthVariantType,
    inputFormat: customTypes.FormatNoTextType,
    options?: customTypes.FixedLengthOptionsNoEncodingType,
  );

  public constructor(
    variant: Sha3VariantType.shake128 | Sha3VariantType.shake256,
    inputFormat: customTypes.FormatType.text,
    options?: customTypes.SHAKEOptionsEncodingType,
  );

  public constructor(
    variant: Sha3VariantType.shake128 | Sha3VariantType.shake256,
    inputFormat: customTypes.FormatNoTextType,
    options?: customTypes.SHAKEOptionsNoEncodingType,
  );

  public constructor(
    variant: Sha3VariantType.cshake128 | Sha3VariantType.cshake256,
    inputFormat: customTypes.FormatType.text,
    options?: customTypes.CSHAKEOptionsEncodingType,
  );

  public constructor(
    variant: Sha3VariantType.cshake128 | Sha3VariantType.cshake256,
    inputFormat: customTypes.FormatNoTextType,
    options?: customTypes.CSHAKEOptionsNoEncodingType,
  );

  public constructor(
    variant: Sha3VariantType.kmac128 | Sha3VariantType.kmac256,
    inputFormat: customTypes.FormatType.text,
    options: customTypes.KMACOptionsEncodingType,
  );

  public constructor(
    variant: Sha3VariantType.kmac128 | Sha3VariantType.kmac256,
    inputFormat: customTypes.FormatNoTextType,
    options: customTypes.KMACOptionsNoEncodingType,
  );

  // eslint-disable-next-line max-lines-per-function
  public constructor(
    variant: Sha3VariantType,
    inputFormat: customTypes.FormatType,
    options?: customTypes.FixedLengthOptionsEncodingType
    | customTypes.FixedLengthOptionsNoEncodingType
    | customTypes.SHAKEOptionsEncodingType
    | customTypes.SHAKEOptionsNoEncodingType
    | customTypes.CSHAKEOptionsEncodingType
    | customTypes.CSHAKEOptionsNoEncodingType
    | customTypes.KMACOptionsEncodingType
    | customTypes.KMACOptionsNoEncodingType,
  ) {
    super(
      {
        bigEndianMod: 1,
        intermediateState: getNewState(),
        ...getVariantCtorState(variant),
      },
      variant,
      inputFormat as customTypes.FormatNoTextType,
      options as customTypes.FixedLengthOptionsEncodingType,
    );
    const resolvedOptions = options ?? {};

    /* In other variants, this was done after variable initialization but need to do it earlier here
     * because we want to avoid KMAC initialization
     */
    if (this.numRounds !== 1) {
      if (
        ("kmacKey" in resolvedOptions && resolvedOptions.kmacKey)
        || ("hmacKey" in resolvedOptions && resolvedOptions.hmacKey)
      ) {
        throw new Error(common.macRoundsError);
      } else if (
        this.shaVariant === Sha3VariantType.cshake128
        || this.shaVariant === Sha3VariantType.cshake256
      ) {
        throw new Error("Cannot set numRounds for CSHAKE variants");
      }
    }

    this.converterFunc = converters.getStrConverter(
      this.inputFormat,
      this.utfType,
      this.bigEndianMod,
    );

    const initValues = this.#getVariantInitState(variant, options);
    this.getMAC = initValues.getMAC;

    /* This needs to be down here as CSHAKE can change its delimiter */
    this.finalizeFunc = (
      remainder,
      remainderBinLen,
      processedBinLen,
      state,
      outputBinLen,
    ): Array<number> => finalizeSHA3(
      remainder,
      remainderBinLen,
      processedBinLen,
      state,
      this.variantBlockSize,
      initValues.delimiter,
      outputBinLen,
    );

    if ("hmacKey" in resolvedOptions && resolvedOptions.hmacKey) {
      this._setHMACKey(
        common.parseInputOption("hmacKey", resolvedOptions.hmacKey, this.bigEndianMod),
      );
    }
  }

  /**
   * Initialize CSHAKE variants.
   *
   * @param options - Options containing CSHAKE params.
   * @param funcNameOverride - Overrides any "funcName" present in `options` (used with KMAC)
   * @returns The delimiter to be used
   */
  protected _initializeCSHAKE = (
    options?: customTypes.CSHAKEOptionsNoEncodingType,
    funcNameOverride?: customTypes.PackedValue,
  ): number => {
    const resolvedOptions = resolveCSHAKEOptions(options ?? {});
    if (funcNameOverride) {
      resolvedOptions.funcName = funcNameOverride;
    }
    const packedParams = common.packedLEConcat(
      encodeString(resolvedOptions.funcName),
      encodeString(resolvedOptions.customization),
    );

    /* CSHAKE is defined to be a call to SHAKE iff both the customization and function-name string are both empty.  This
       can be accomplished by processing nothing in this step. */
    if (resolvedOptions.customization.binLen !== 0 || resolvedOptions.funcName.binLen !== 0) {
      const bytePadOut = bytePad(packedParams, this.variantBlockSize >>> 3);
      for (let i = 0; i < bytePadOut.length; i += this.variantBlockSize >>> 5) {
        this.intermediateState = this.roundFunc(
          bytePadOut.slice(i, i + (this.variantBlockSize >>> 5)),
          this.intermediateState,
        );
        this.processedLen += this.variantBlockSize;
      }
      return 0x04;
    }
    return 0x1f;
  };

  /**
   * Initialize KMAC variants.
   *
   * @param options - Options containing KMAC params.
   */
  protected _initializeKMAC = (
    options: customTypes.KMACOptionsNoEncodingType | undefined,
  ): void => {
    if (!options) throw new Error("missing options");
    const resolvedOptions = resolveKMACOptions(options);

    this._initializeCSHAKE(options, resolvedOptions.funcName);
    const bytePadOut = bytePad(encodeString(resolvedOptions.kmacKey), this.variantBlockSize >>> 3);
    for (let i = 0; i < bytePadOut.length; i += this.variantBlockSize >>> 5) {
      this.intermediateState = this.roundFunc(
        bytePadOut.slice(i, i + (this.variantBlockSize >>> 5)),
        this.intermediateState,
      );
      this.processedLen += this.variantBlockSize;
    }
    this.macKeySet = true;
  };

  /**
   * Returns the the KMAC in the specified format.
   *
   * @param options - Hashmap of extra outputs options. `outputLen` must be specified.
   * @returns The KMAC in the format specified.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected _getKMAC = (options: { outputLen: number }): Array<number> => {
    const concatedRemainder = common.packedLEConcat(
      {value: this.remainder.slice(), binLen: this.remainderLen},
      rightEncode(options.outputLen),
    );

    return this.finalizeFunc(
      concatedRemainder.value,
      concatedRemainder.binLen,
      this.processedLen,
      this.stateCloneFunc(this.intermediateState),
      options.outputLen,
    );
  };

  #getVariantInitState = (
    variant: Sha3VariantType,
    options?: customTypes.FixedLengthOptionsEncodingType
    | customTypes.FixedLengthOptionsNoEncodingType
    | customTypes.SHAKEOptionsEncodingType
    | customTypes.SHAKEOptionsNoEncodingType
    | customTypes.CSHAKEOptionsEncodingType
    | customTypes.CSHAKEOptionsNoEncodingType
    | customTypes.KMACOptionsEncodingType
    | customTypes.KMACOptionsNoEncodingType,
  ): {getMAC: customTypes.GetMacFunc | null; delimiter: number} => {
    switch (variant) {
    case Sha3VariantType.sha3224:
    case Sha3VariantType.sha3256:
    case Sha3VariantType.sha3384:
    case Sha3VariantType.sha3512:
      return {delimiter: 0x06, getMAC: this._getHMAC};
    case Sha3VariantType.shake128:
    case Sha3VariantType.shake256:
      return {delimiter: 0x1f, getMAC: null};
    case Sha3VariantType.kmac128:
    case Sha3VariantType.kmac256:
      this._initializeKMAC(options as customTypes.KMACOptionsEncodingType);
      return {delimiter: 0x04, getMAC: this._getKMAC};
    case Sha3VariantType.cshake128:
    case Sha3VariantType.cshake256:
      return {
        delimiter: this._initializeCSHAKE(options as customTypes.CSHAKEOptionsEncodingType),
        getMAC: null,
      };
    }
  };
}
