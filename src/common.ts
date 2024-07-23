/* eslint-disable max-lines-per-function */
/* eslint-disable @typescript-eslint/no-magic-numbers */
import * as converters from "./converters.js";

import * as customTypes from "./custom_types.js";

export interface GetHashOptionsHex {
  outputUpper?: boolean;
  outputLen?: number;
  shakeLen?: number;
}

export interface GetHashOptionsB64 {
  b64Pad?: string;
  outputLen?: number;
  shakeLen?: number;
}

export interface GetHashOptionsBinary {
  outputLen?: number;
  shakeLen?: number;
}

export type GetHashOptions =
| GetHashOptionsHex
| GetHashOptionsB64
| GetHashOptionsBinary;

export interface GetHmacOptionsHex {
  outputUpper?: boolean;
}

export interface GetHmacOptionsB64 {
  b64Pad?: string;
}

export type GetHmacOptions = GetHmacOptionsHex | GetHmacOptionsB64;

export const TWO_PWR_32 = 4294967296;

/* Constant used in SHA-2 families */
export const kSha2 = [
  0x428a2f98,
  0x71374491,
  0xb5c0fbcf,
  0xe9b5dba5,
  0x3956c25b,
  0x59f111f1,
  0x923f82a4,
  0xab1c5ed5,
  0xd807aa98,
  0x12835b01,
  0x243185be,
  0x550c7dc3,
  0x72be5d74,
  0x80deb1fe,
  0x9bdc06a7,
  0xc19bf174,
  0xe49b69c1,
  0xefbe4786,
  0x0fc19dc6,
  0x240ca1cc,
  0x2de92c6f,
  0x4a7484aa,
  0x5cb0a9dc,
  0x76f988da,
  0x983e5152,
  0xa831c66d,
  0xb00327c8,
  0xbf597fc7,
  0xc6e00bf3,
  0xd5a79147,
  0x06ca6351,
  0x14292967,
  0x27b70a85,
  0x2e1b2138,
  0x4d2c6dfc,
  0x53380d13,
  0x650a7354,
  0x766a0abb,
  0x81c2c92e,
  0x92722c85,
  0xa2bfe8a1,
  0xa81a664b,
  0xc24b8b70,
  0xc76c51a3,
  0xd192e819,
  0xd6990624,
  0xf40e3585,
  0x106aa070,
  0x19a4c116,
  0x1e376c08,
  0x2748774c,
  0x34b0bcb5,
  0x391c0cb3,
  0x4ed8aa4a,
  0x5b9cca4f,
  0x682e6ff3,
  0x748f82ee,
  0x78a5636f,
  0x84c87814,
  0x8cc70208,
  0x90befffa,
  0xa4506ceb,
  0xbef9a3f7,
  0xc67178f2,
];

/* Constant used in SHA-2 families */
export const hTrunc = [
  0xc1059ed8,
  0x367cd507,
  0x3070dd17,
  0xf70e5939,
  0xffc00b31,
  0x68581511,
  0x64f98fa7,
  0xbefa4fa4,
];

/* Constant used in SHA-2 families */
export const hFull = [
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
];

export const shaVariantError = "Chosen SHA variant is not supported";
export const macRoundsError = "Cannot set numRounds with MAC";

/**
 * Concatenates 2 packed arrays. Clobbers array `a`.
 *
 * @param a - First array to concatenate.
 * @param b - Second array to concatenate.
 * @returns The concatentation of `a` + `b`.
 */
export const packedLEConcat = (
  a: customTypes.PackedValue,
  b: customTypes.PackedValue,
): customTypes.PackedValue => {
  let i, arrOffset;
  const aByteLen = a.binLen >>> 3;
  const bByteLen = b.binLen >>> 3;
  const leftShiftAmount = aByteLen << 3;
  const rightShiftAmount = (4 - aByteLen) << 3;

  /* If a only contains "full" integers, we can just use concat which is so much easier */
  if (aByteLen % 4 !== 0) {
    for (i = 0; i < bByteLen; i += 4) {
      arrOffset = (aByteLen + i) >>> 2;
      /* Left shift chops off bits over 32-bits */
      a.value[arrOffset] |= b.value[i >>> 2] << leftShiftAmount;
      a.value.push(0);
      a.value[arrOffset + 1] |= b.value[i >>> 2] >>> rightShiftAmount;
    }

    /* Since an unconditional push was performed above, we may have pushed an extra value if it
     * could have been encoded without it.  Check if popping an int off (reducing total length by 4
     * bytes) is still bigger than the needed size.
     */
    if ((a.value.length << 2) - 4 >= bByteLen + aByteLen) a.value.pop();

    return {value: a.value, binLen: a.binLen + b.binLen};
  }
  return {value: a.value.concat(b.value), binLen: a.binLen + b.binLen};
};

/**
 * Validate hash list containing output formatting options, ensuring presence of every option or
 * adding the default value.
 *
 * @param options - Hashmap of output formatting options from user.
 * @returns Validated hashmap containing output formatting options.
 */
export const getOutputOpts = (options?: {
  outputUpper?: boolean;
  b64Pad?: string;
  shakeLen?: number;
  outputLen?: number;
}): { outputUpper: boolean; b64Pad: string; outputLen: number } => {
  const retVal = {outputUpper: false, b64Pad: "=", outputLen: -1};
  const outputOptions: {
    outputUpper?: boolean;
    b64Pad?: string;
    shakeLen?: number;
    outputLen?: number;
  } = options ?? {};
  const lenErrstr = "Output length must be a multiple of 8";

  retVal.outputUpper = outputOptions.outputUpper ?? false;

  if (outputOptions.b64Pad) retVal.b64Pad = outputOptions.b64Pad;

  if (outputOptions.outputLen) {
    if (outputOptions.outputLen % 8 !== 0) throw new Error(lenErrstr);
    retVal.outputLen = outputOptions.outputLen;
  } else if (outputOptions.shakeLen) {
    if (outputOptions.shakeLen % 8 !== 0) throw new Error(lenErrstr);
    retVal.outputLen = outputOptions.shakeLen;
  }

  if ("boolean" !== typeof retVal.outputUpper) {
    throw new Error("Invalid outputUpper formatting option");
  }

  if ("string" !== typeof retVal.b64Pad) throw new Error("Invalid b64Pad formatting option");

  return retVal;
};

/**
 * Parses an external constructor object and returns a packed number, if possible.
 *
 * @param key - The human-friendly key name to prefix any errors with
 * @param value - The input value object to parse
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @param fallback - Fallback value if `value` is undefined.  If not present and `value` is
 * undefined, an Error is thrown
 */
export const parseInputOption = (
  key: string,
  value: customTypes.GenericInputType | undefined,
  bigEndianMod: customTypes.BigEndianMod,
  fallback?: customTypes.PackedValue,
): customTypes.PackedValue => {
  const errStr = `${key} must include a value and format`;
  if (!value) {
    if (!fallback) throw new Error(errStr);
    return fallback;
  }

  const encoding = (value.format === customTypes.FormatType.text ? value.encoding : undefined)
    ?? customTypes.EncodingType.utf8;

  const converter = converters.getStrConverter(
    value.format,
    encoding,
    bigEndianMod,
  );
  return converter(value.value);
};

export interface CtorState<StateT> {
  intermediateState: StateT;
  variantBlockSize: number;
  bigEndianMod: customTypes.BigEndianMod;
  outputBinLen: number;
  isVariableLen: boolean;
  hmacSupported: boolean;
}

export abstract class JsSHABase<StateT, VariantT> {
  /**
   * @param variant - The desired SHA variant.
   * @param inputFormat - The input format to be used in future `update` calls.
   * @param options - Hashmap of extra input options.
   */
  /* Needed inputs */
  protected readonly shaVariant: VariantT;
  protected readonly inputFormat: customTypes.FormatType;
  protected readonly utfType: customTypes.EncodingType;
  protected readonly numRounds: number;

  /* State */
  protected keyWithIPad: Array<number>;
  protected keyWithOPad: Array<number>;
  protected remainder: Array<number>;
  protected remainderLen: number;
  protected updateCalled: boolean;
  protected processedLen: number;
  protected macKeySet: boolean;

  protected intermediateState: StateT;

  /* Variant specifics */
  protected readonly variantBlockSize: number;
  protected readonly bigEndianMod: customTypes.BigEndianMod;
  protected readonly outputBinLen: number;
  protected readonly isVariableLen: boolean;
  protected readonly hmacSupported: boolean;

  /* Functions */
  protected abstract readonly converterFunc: converters.GenericConverter;
  protected abstract readonly roundFunc: customTypes.RoundFunc<StateT>;
  protected abstract readonly finalizeFunc: customTypes.FinalizeFunc<StateT>;
  protected abstract readonly stateCloneFunc: customTypes.StateCloneFunc<StateT>;
  protected abstract readonly newStateFunc: customTypes.NewStateFunc<StateT, VariantT>;
  protected abstract readonly getMAC: customTypes.GetMacFunc | null;

  protected constructor(
    ctorState: CtorState<StateT>,
    variant: VariantT,
    inputFormat: customTypes.FormatType.text,
    options?: customTypes.FixedLengthOptionsEncodingType,
  );

  protected constructor(
    ctorState: CtorState<StateT>,
    variant: VariantT,
    inputFormat: customTypes.FormatNoTextType,
    options?: customTypes.FixedLengthOptionsNoEncodingType,
  );

  protected constructor(
    ctorState: CtorState<StateT>,
    variant: VariantT,
    inputFormat: customTypes.FormatType,
    options?: customTypes.FixedLengthOptionsEncodingType
    | customTypes.FixedLengthOptionsNoEncodingType,
  ) {
    const inputOptions = options ?? {};
    this.inputFormat = inputFormat as customTypes.FormatType;

    this.utfType = (inputOptions as customTypes.FixedLengthOptionsEncodingType).encoding
      ?? customTypes.EncodingType.utf8;
    this.numRounds = (inputOptions as {numRounds?: number}).numRounds ?? 1;

    if (
      isNaN(this.numRounds)
      || this.numRounds !== parseInt(this.numRounds.toString(), 10)
      || 1 > this.numRounds
    ) {
      throw new Error("numRounds must a integer >= 1");
    }

    this.shaVariant = variant;
    this.remainder = [];
    this.remainderLen = 0;
    this.updateCalled = false;
    this.processedLen = 0;
    this.macKeySet = false;
    this.keyWithIPad = [];
    this.keyWithOPad = [];

    this.intermediateState = ctorState.intermediateState;
    this.variantBlockSize = ctorState.variantBlockSize;
    this.bigEndianMod = ctorState.bigEndianMod;
    this.outputBinLen = ctorState.outputBinLen;
    this.isVariableLen = ctorState.isVariableLen;
    this.hmacSupported = ctorState.hmacSupported;
  }

  /**
   * Hashes as many blocks as possible.  Stores the rest for either a future update or getHash call.
   *
   * @param srcString - The input to be hashed.
   * @returns A reference to the object.
   */
  public update = (srcString: string | ArrayBuffer | Uint8Array): this => {
    let updateProcessedLen = 0;
    const variantBlockIntInc = this.variantBlockSize >>> 5;
    const convertRet = this.converterFunc(srcString, this.remainder, this.remainderLen);
    const chunkBinLen = convertRet.binLen;
    const chunk = convertRet.value;
    const chunkIntLen = chunkBinLen >>> 5;

    for (let i = 0; i < chunkIntLen; i += variantBlockIntInc) {
      if (updateProcessedLen + this.variantBlockSize <= chunkBinLen) {
        this.intermediateState = this.roundFunc(
          chunk.slice(i, i + variantBlockIntInc),
          this.intermediateState,
        );
        updateProcessedLen += this.variantBlockSize;
      }
    }
    this.processedLen += updateProcessedLen;
    this.remainder = chunk.slice(updateProcessedLen >>> 5);
    this.remainderLen = chunkBinLen % this.variantBlockSize;
    this.updateCalled = true;

    return this;
  };

  /**
   * Returns the desired SHA hash of the input fed in via `update` calls.
   *
   * @param format - The desired output formatting
   * @param options - Hashmap of output formatting options. `outputLen` must be specified for
   * variable length hashes. `outputLen` replaces the now deprecated `shakeLen` key.
   * @returns The hash in the format specified.
   */
  public getHash(format: customTypes.FormatType.hex, options?: GetHashOptionsHex): string;

  public getHash(format: customTypes.FormatType.b64, options?: GetHashOptionsB64): string;

  public getHash(format: customTypes.FormatType.bytes, options?: GetHashOptionsBinary): string;

  public getHash(
    format: customTypes.FormatType.uint8Array,
    options?: GetHashOptionsBinary,
  ): Uint8Array;

  public getHash(
    format: customTypes.FormatType.arrayBuffer,
    options?: GetHashOptionsBinary,
  ): ArrayBuffer;

  public getHash(format: customTypes.FormatNoTextType, options?: GetHashOptions): unknown {
    let outputBinLen = this.outputBinLen;

    const outputOptions = getOutputOpts(options);

    if (this.isVariableLen) {
      if (outputOptions.outputLen === -1) {
        throw new Error("Output length must be specified in options");
      }
      outputBinLen = outputOptions.outputLen;
    }

    let formatFunc;
    switch (format) {
    case customTypes.FormatType.b64:
    case customTypes.FormatType.hex:
    case customTypes.FormatType.bytes:
      formatFunc = converters.getOutputConverter(
        format,
        outputBinLen,
        this.bigEndianMod,
        outputOptions,
      );
      break;
    case customTypes.FormatType.arrayBuffer:
      formatFunc = converters.getOutputConverter(
        format,
        outputBinLen,
        this.bigEndianMod,
        outputOptions,
      );
      break;
    case customTypes.FormatType.uint8Array:
      formatFunc = converters.getOutputConverter(
        format,
        outputBinLen,
        this.bigEndianMod,
        outputOptions,
      );
      break;
    }
    if (this.macKeySet && this.getMAC) return formatFunc(this.getMAC(outputOptions));

    let finalizedState = this.finalizeFunc(
      this.remainder.slice(),
      this.remainderLen,
      this.processedLen,
      this.stateCloneFunc(this.intermediateState),
      outputBinLen,
    );
    for (let i = 1; i < this.numRounds; i += 1) {
      /* Need to mask out bits that should be zero due to output not being a multiple of 32 */
      if (this.isVariableLen && outputBinLen % 32 !== 0) {
        finalizedState[finalizedState.length - 1] &= 0x00ffffff >>> (24 - (outputBinLen % 32));
      }
      finalizedState = this.finalizeFunc(
        finalizedState,
        outputBinLen,
        0,
        this.newStateFunc(this.shaVariant),
        outputBinLen,
      );
    }

    return formatFunc(finalizedState);
  }

  /**
   * Sets the HMAC key for an eventual `getHMAC` call.  Must be called immediately after jsSHA
   * object instantiation.
   *
   * @param key - The key used to calculate the HMAC
   * @param inputFormat - The format of key.
   * @param options - Hashmap of extra input options.
   */
  public setHMACKey(
    key: string,
    inputFormat: customTypes.FormatType.text,
    options?: {encoding?: customTypes.EncodingType},
  ): void;

  public setHMACKey(
    key: string,
    inputFormat: customTypes.FormatType.b64
    | customTypes.FormatType.hex
    | customTypes.FormatType.bytes,
  ): void;

  public setHMACKey(
    key: ArrayBuffer,
    inputFormat: customTypes.FormatType.arrayBuffer,
  ): void;

  public setHMACKey(
    key: Uint8Array,
    inputFormat: customTypes.FormatType.uint8Array,
  ): void;

  public setHMACKey(
    key: string | ArrayBuffer | Uint8Array,
    inputFormat: customTypes.FormatType,
    options?: {encoding?: customTypes.EncodingType},
  ): void {
    if (!this.hmacSupported) throw new Error("Variant does not support HMAC");
    if (this.updateCalled) throw new Error("Cannot set MAC key after calling update");

    const keyOptions = options ?? {};
    const keyConverterFunc = converters.getStrConverter(
      inputFormat,
      keyOptions.encoding ?? customTypes.EncodingType.utf8,
      this.bigEndianMod,
    );

    this._setHMACKey(keyConverterFunc(key));
  }

  /**
   * Returns the the HMAC in the specified format using the key given by a previous `setHMACKey`
   * call.
   *
   * @param format - The desired output formatting.
   * @param options - Hashmap of extra outputs options.
   * @returns The HMAC in the format specified.
   */
  public getHMAC(format: customTypes.FormatType.hex, options?: GetHmacOptionsHex): string;

  public getHMAC(format: customTypes.FormatType.b64, options?: GetHmacOptionsB64): string;

  public getHMAC(format: customTypes.FormatType.bytes): string;

  public getHMAC(format: customTypes.FormatType.uint8Array): Uint8Array;

  public getHMAC(format: customTypes.FormatType.arrayBuffer): ArrayBuffer;

  public getHMAC(format: customTypes.FormatNoTextType, options?: GetHmacOptions): unknown {
    const outputOptions = getOutputOpts(options);
    let formatFunc;
    switch (format) {
    case customTypes.FormatType.b64:
    case customTypes.FormatType.hex:
    case customTypes.FormatType.bytes:
      formatFunc = converters.getOutputConverter(
        format,
        this.outputBinLen,
        this.bigEndianMod,
        outputOptions,
      );
      break;
    case customTypes.FormatType.arrayBuffer:
      formatFunc = converters.getOutputConverter(
        format,
        this.outputBinLen,
        this.bigEndianMod,
        outputOptions,
      );
      break;
    case customTypes.FormatType.uint8Array:
      formatFunc = converters.getOutputConverter(
        format,
        this.outputBinLen,
        this.bigEndianMod,
        outputOptions,
      );
      break;
    }
    return formatFunc(this._getHMAC());
  }

  /**
   * Internal function that sets the MAC key.
   *
   * @param key - The packed MAC key to use
   */
  protected _setHMACKey = (key: customTypes.PackedValue): void => {
    const blockByteSize = this.variantBlockSize >>> 3;
    const lastArrayIndex = (blockByteSize / 4) - 1;
    if (this.numRounds !== 1) throw new Error(macRoundsError);

    if (this.macKeySet) throw new Error("MAC key already set");

    /* Figure out what to do with the key based on its size relative to
     * the hash's block size */
    if (blockByteSize < key.binLen / 8) {
      key.value = this.finalizeFunc(
        key.value,
        key.binLen,
        0,
        this.newStateFunc(this.shaVariant),
        this.outputBinLen,
      );
    }
    while (key.value.length <= lastArrayIndex) key.value.push(0);
    /* Create ipad and opad */
    for (let i = 0; i <= lastArrayIndex; i += 1) {
      this.keyWithIPad[i] = key.value[i] ^ 0x36363636;
      this.keyWithOPad[i] = key.value[i] ^ 0x5c5c5c5c;
    }

    this.intermediateState = this.roundFunc(this.keyWithIPad, this.intermediateState);
    this.processedLen = this.variantBlockSize;

    this.macKeySet = true;
  };

  /** Internal function that returns the "raw" HMAC */
  protected _getHMAC = (): Array<number> => {
    let finalizedState;

    if (!this.macKeySet) {
      throw new Error("Cannot call getHMAC without first setting MAC key");
    }

    const firstHash = this.finalizeFunc(
      this.remainder.slice(),
      this.remainderLen,
      this.processedLen,
      this.stateCloneFunc(this.intermediateState),
      this.outputBinLen,
    );
    finalizedState = this.roundFunc(this.keyWithOPad, this.newStateFunc(this.shaVariant));
    finalizedState = this.finalizeFunc(
      firstHash,
      this.outputBinLen,
      this.variantBlockSize,
      finalizedState,
      this.outputBinLen,
    );

    return finalizedState;
  };
}
