/* eslint-disable @typescript-eslint/no-magic-numbers */
/* eslint-disable max-lines-per-function */
import * as customTypes from "./custom_types.js";

/**
 * Return type for all the *2packed functions
 */
const b64Tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Convert a string to an array of words.
 *
 * There is a known bug with an odd number of existing bytes and using a UTF-16 encoding.  However,
 * this function is used such that the existing bytes are always a result of a previous UTF-16
 * str2packed call and therefore there should never be an odd number of existing bytes.

 * @param str - Unicode string to be converted to binary representation.
 * @param utfType - The Unicode type to use to encode the source string.
 * @param existingPacked - A packed int array of bytes to append the results to.
 * @param existingPackedLenIn - The number of bits in `existingPacked`.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @returns Hashmap of the packed values.
 */
const str2packed = (
  str: string,
  utfType: customTypes.EncodingType,
  existingPacked: Array<number> | undefined,
  existingPackedLenIn: number | undefined,
  bigEndianMod: customTypes.BigEndianMod,
): customTypes.PackedValue => {
  const packed = existingPacked ?? [0];
  const existingPackedLen = existingPackedLenIn ?? 0;
  const existingByteLen = existingPackedLen >>> 3;
  let shiftModifier;
  let byteCnt = 0;

  if (customTypes.EncodingType.utf8 === utfType) {
    shiftModifier = bigEndianMod === -1 ? 3 : 0;
    for (let i = 0; i < str.length; i += 1) {
      let codePnt = str.charCodeAt(i);
      const codePntArr = [];

      if (0x80 > codePnt) {
        codePntArr.push(codePnt);
      } else if (0x800 > codePnt) {
        codePntArr.push(0xc0 | (codePnt >>> 6));
        codePntArr.push(0x80 | (codePnt & 0x3f));
      } else if (0xd800 > codePnt || 0xe000 <= codePnt) {
        codePntArr.push(
          0xe0 | (codePnt >>> 12),
          0x80 | ((codePnt >>> 6) & 0x3f),
          0x80 | (codePnt & 0x3f),
        );
      } else {
        i += 1;
        codePnt = 0x10000 + (((codePnt & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
        codePntArr.push(
          0xf0 | (codePnt >>> 18),
          0x80 | ((codePnt >>> 12) & 0x3f),
          0x80 | ((codePnt >>> 6) & 0x3f),
          0x80 | (codePnt & 0x3f),
        );
      }

      for (const cPntElem of codePntArr) {
        const byteOffset = byteCnt + existingByteLen;
        const intOffset = byteOffset >>> 2;
        while (packed.length <= intOffset) packed.push(0);
        /* Known bug kicks in here */
        packed[intOffset] |= cPntElem << (8 * (shiftModifier + (bigEndianMod * (byteOffset % 4))));
        byteCnt += 1;
      }
    }
  } else {
    /* UTF16BE or UTF16LE */
    shiftModifier = bigEndianMod === -1 ? 2 : 0;
    /* Internally strings are UTF-16BE so transpose bytes under two conditions:
     * need LE and not switching endianness due to SHA-3
     * need BE and switching endianness due to SHA-3 */
    const transposeBytes = (customTypes.EncodingType.utf16LE === utfType && bigEndianMod !== 1)
    || (customTypes.EncodingType.utf16LE !== utfType && bigEndianMod === 1);
    for (let i = 0; i < str.length; i += 1) {
      let codePnt = str.charCodeAt(i);
      if (transposeBytes) {
        const j = codePnt & 0xff;
        codePnt = (j << 8) | (codePnt >>> 8);
      }

      const byteOffset = byteCnt + existingByteLen;
      const intOffset = byteOffset >>> 2;
      while (packed.length <= intOffset) packed.push(0);
      packed[intOffset] |= codePnt << (8 * (shiftModifier + (bigEndianMod * (byteOffset % 4))));
      byteCnt += 2;
    }
  }
  return {value: packed, binLen: (byteCnt * 8) + existingPackedLen};
};

/**
 * Convert a hex string to an array of words.
 *
 * @param str - Hexadecimal string to be converted to binary representation.
 * @param existingPacked - A packed int array of bytes to append the results to.
 * @param existingPackedLenIn - The number of bits in `existingPacked` array.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @returns Hashmap of the packed values.
 */
const hex2packed = (
  str: string,
  existingPacked: Array<number> | undefined,
  existingPackedLenIn: number | undefined,
  bigEndianMod: customTypes.BigEndianMod,
): customTypes.PackedValue => {
  if (0 !== str.length % 2) throw new Error("String of HEX type must be in byte increments");

  const packed = existingPacked ?? [0];
  const existingPackedLen = existingPackedLenIn ?? 0;
  const existingByteLen = existingPackedLen >>> 3;
  const shiftModifier = bigEndianMod === -1 ? 3 : 0;

  for (let i = 0; i < str.length; i += 2) {
    const num = parseInt(str.substring(i, i + 2), 16);
    if (isNaN(num)) {
      throw new Error("String of HEX type contains invalid characters");
    } else {
      const byteOffset = (i >>> 1) + existingByteLen;
      const intOffset = byteOffset >>> 2;
      while (packed.length <= intOffset) packed.push(0);
      packed[intOffset] |= num << (8 * (shiftModifier + (bigEndianMod * (byteOffset % 4))));
    }
  }

  return {value: packed, binLen: (str.length * 4) + existingPackedLen};
};

/**
 * Convert a string of raw bytes to an array of words.
 *
 * @param str - String of raw bytes to be converted to binary representation.
 * @param existingPacked - A packed int array of bytes to append the results to.
 * @param existingPackedLen - The number of bits in `existingPacked` array.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @returns Hashmap of the packed values.
 */
const bytes2packed = (
  str: string,
  existingPacked: Array<number> | undefined,
  existingPackedLenIn: number | undefined,
  bigEndianMod: customTypes.BigEndianMod,
): customTypes.PackedValue => {
  const packed = existingPacked ?? [0];
  const existingPackedLen = existingPackedLenIn ?? 0;
  const existingByteLen = existingPackedLen >>> 3;
  const shiftModifier = bigEndianMod === -1 ? 3 : 0;

  for (let i = 0; i < str.length; i += 1) {
    const codePnt = str.charCodeAt(i);

    const byteOffset = i + existingByteLen;
    const intOffset = byteOffset >>> 2;
    if (packed.length <= intOffset) packed.push(0);
    packed[intOffset] |= codePnt << (8 * (shiftModifier + (bigEndianMod * (byteOffset % 4))));
  }

  return {value: packed, binLen: (str.length * 8) + existingPackedLen};
};

/**
 * Convert a base-64 string to an array of words.
 *
 * @param str - Base64-encoded string to be converted to binary representation.
 * @param existingPacked - A packed int array of bytes to append the results to.
 * @param existingPackedLenIn - The number of bits in `existingPacked` array.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @returns Hashmap of the packed values.
 */
const b642packed = (
  strIn: string,
  existingPacked: Array<number> | undefined,
  existingPackedLenIn: number | undefined,
  bigEndianMod: customTypes.BigEndianMod,
): customTypes.PackedValue => {
  let byteCnt = 0;
  const existingPackedLen = existingPackedLenIn ?? 0;
  const packed = existingPacked ?? [0];
  const existingByteLen = existingPackedLen >>> 3;
  const shiftModifier = bigEndianMod === -1 ? 3 : 0;
  const firstEqual = strIn.indexOf("=");

  if (-1 === strIn.search(/^[a-zA-Z0-9=+/]+$/u)) {
    throw new Error("Invalid character in base-64 string");
  }

  const str = strIn.replace(/[=]/gu, "");
  if (-1 !== firstEqual && firstEqual < str.length) {
    throw new Error("Invalid '=' found in base-64 string");
  }

  for (let i = 0; i < str.length; i += 4) {
    const strPart = str.substring(i, i + 4);
    let tmpInt = 0;

    for (let j = 0; j < strPart.length; j += 1) {
      const index = b64Tab.indexOf(strPart.charAt(j));
      tmpInt |= index << (18 - (6 * j));
    }

    for (let j = 0; j < strPart.length - 1; j += 1) {
      const byteOffset = byteCnt + existingByteLen;
      const intOffset = byteOffset >>> 2;
      while (packed.length <= intOffset) packed.push(0);
      packed[intOffset] |= ((tmpInt >>> (16 - (j * 8))) & 0xff)
        << (8 * (shiftModifier + (bigEndianMod * (byteOffset % 4))));
      byteCnt += 1;
    }
  }

  return {value: packed, binLen: (byteCnt * 8) + existingPackedLen};
};

/**
 * Convert an Uint8Array to an array of words.
 *
 * @param arr - Uint8Array to be converted to binary representation.
 * @param existingPacked - A packed int array of bytes to append the results to.
 * @param existingPackedLenIn - The number of bits in `existingPacked` array.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @returns Hashmap of the packed values.
 */
const uint8array2packed = (
  arr: Uint8Array,
  existingPacked: Array<number> | undefined,
  existingPackedLenIn: number | undefined,
  bigEndianMod: customTypes.BigEndianMod,
): customTypes.PackedValue => {
  const existingPackedLen = existingPackedLenIn ?? 0;

  const packed = existingPacked ?? [0];
  const existingByteLen = existingPackedLen >>> 3;
  const shiftModifier = bigEndianMod === -1 ? 3 : 0;

  for (let i = 0; i < arr.length; i += 1) {
    const byteOffset = i + existingByteLen;
    const intOffset = byteOffset >>> 2;
    if (packed.length <= intOffset) packed.push(0);
    packed[intOffset] |= arr[i] << (8 * (shiftModifier + (bigEndianMod * (byteOffset % 4))));
  }

  return {value: packed, binLen: (arr.length * 8) + existingPackedLen};
};

/**
 * Convert an ArrayBuffer to an array of words
 *
 * @param arr - ArrayBuffer to be converted to binary representation.
 * @param existingPacked - A packed int array of bytes to append the results to.
 * @param existingPackedLen - The number of bits in `existingPacked` array.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @returns Hashmap of the packed values.
 */
const arraybuffer2packed = (
  arr: ArrayBuffer,
  existingPacked: Array<number> | undefined,
  existingPackedLen: number | undefined,
  bigEndianMod: customTypes.BigEndianMod,
): customTypes.PackedValue => uint8array2packed(
  new Uint8Array(arr),
  existingPacked,
  existingPackedLen,
  bigEndianMod,
);

/**
 * @param input - Suitable input depending on the selected input format
 * @param existingPacked - A packed int array of bytes to append the results to.
 * @param existingPackedLen - The number of bits in `existingPacked` array.
 * @returns Hashmap of the packed values.
 */
export type GenericConverter = (
  input: string | Uint8Array | ArrayBuffer,
  existingBin?: Array<number>,
  existingBinLen?: number,
) => customTypes.PackedValue;

/**
 * Function that takes an input format and UTF encoding and returns the appropriate function used to
 * convert the input.
 *
 * @param format - The format of the input to be converted
 * @param utfType - The string encoding to use for TEXT inputs.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian
 * @returns Function that will convert an input to a packed int array.
 */
// eslint-disable-next-line func-style
export const getStrConverter = (
  format: customTypes.FormatType,
  utfType: customTypes.EncodingType,
  bigEndianMod: customTypes.BigEndianMod,
): GenericConverter => {
  /* Map inputFormat to the appropriate converter */
  switch (format) {
  case customTypes.FormatType.hex:
    return (
      str: unknown,
      existingBin?: Array<number>,
      existingBinLen?: number,
    ): customTypes.PackedValue => hex2packed(
      str as string,
      existingBin,
      existingBinLen,
      bigEndianMod,
    );
  case customTypes.FormatType.text:
    return (
      str: unknown,
      existingBin?: Array<number>,
      existingBinLen?: number,
    ): customTypes.PackedValue => str2packed(
      str as string,
      utfType,
      existingBin,
      existingBinLen,
      bigEndianMod,
    );
  case customTypes.FormatType.b64:
    return (
      str: unknown,
      existingBin?: Array<number>,
      existingBinLen?: number,
    ): customTypes.PackedValue => b642packed(
      str as string,
      existingBin,
      existingBinLen,
      bigEndianMod,
    );
  case customTypes.FormatType.bytes:
    return (
      str: unknown,
      existingBin?: Array<number>,
      existingBinLen?: number,
    ): customTypes.PackedValue => bytes2packed(
      str as string,
      existingBin,
      existingBinLen,
      bigEndianMod,
    );
  case customTypes.FormatType.arrayBuffer:
    return (
      arr: unknown,
      existingBin?: Array<number>,
      existingBinLen?: number,
    ): customTypes.PackedValue => arraybuffer2packed(
      arr as ArrayBuffer,
      existingBin,
      existingBinLen,
      bigEndianMod,
    );
  case customTypes.FormatType.uint8Array:
    return (
      arr: unknown,
      existingBin?: Array<number>,
      existingBinLen?: number,
    ): customTypes.PackedValue => uint8array2packed(
      arr as Uint8Array,
      existingBin,
      existingBinLen,
      bigEndianMod,
    );
  default:
    throw new Error("format must be HEX, TEXT, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY");
  }
};

/**
 * Convert an array of words to a hexadecimal string.
 *
 * toString() won't work here because it removes preceding zeros (e.g. 0x00000001.toString === "1"
 * rather than "00000001" and 0.toString(16) === "0" rather than "00").
 *
 * @param packed - Array of integers to be converted.
 * @param outputLength - Length of output in bits.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @param formatOpts - Hashmap containing validated output formatting options.
 * @returns Hexadecimal representation of `packed`.
 */
export const packed2hex = (
  packed: Array<number>,
  outputLength: number,
  bigEndianMod: customTypes.BigEndianMod,
  formatOpts: {outputUpper: boolean; b64Pad: string},
): string => {
  const hexTab = "0123456789abcdef";
  let str = "";

  const length = outputLength / 8;
  const shiftModifier = bigEndianMod === -1 ? 3 : 0;

  for (let i = 0; i < length; i += 1) {
    /* The below is more than a byte but it gets taken care of later */
    const srcByte = packed[i >>> 2] >>> (8 * (shiftModifier + (bigEndianMod * (i % 4))));
    str += hexTab.charAt((srcByte >>> 4) & 0xf) + hexTab.charAt(srcByte & 0xf);
  }
  return formatOpts["outputUpper"] ? str.toUpperCase() : str;
};

/**
 * Convert an array of words to a base-64 string.
 *
 * @param packed - Array of integers to be converted.
 * @param outputLength - Length of output in bits.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @param formatOpts - Hashmap containing validated output formatting options.
 * @returns Base64-encoded representation of `packed`.
 */
export const packed2b64 = (
  packed: Array<number>,
  outputLength: number,
  bigEndianMod: customTypes.BigEndianMod,
  formatOpts: { outputUpper: boolean; b64Pad: string },
): string => {
  let str = "";

  const length = outputLength / 8;
  const shiftModifier = bigEndianMod === -1 ? 3 : 0;

  for (let i = 0; i < length; i += 3) {
    const int1 = i + 1 < length ? packed[(i + 1) >>> 2] : 0;
    const int2 = i + 2 < length ? packed[(i + 2) >>> 2] : 0;
    const triplet
      = (((packed[i >>> 2] >>> (8 * (shiftModifier + (bigEndianMod * (i % 4))))) & 0xff) << 16)
      | (((int1 >>> (8 * (shiftModifier + (bigEndianMod * ((i + 1) % 4))))) & 0xff) << 8)
      | ((int2 >>> (8 * (shiftModifier + (bigEndianMod * ((i + 2) % 4))))) & 0xff);
    for (let j = 0; j < 4; j += 1) {
      if ((i * 8) + (j * 6) <= outputLength) {
        str += b64Tab.charAt((triplet >>> (6 * (3 - j))) & 0x3f);
      } else {
        str += formatOpts["b64Pad"];
      }
    }
  }
  return str;
};

/**
 * Convert an array of words to raw bytes string.
 *
 * @param packed - Array of integers to be converted.
 * @param outputLength - Length of output in bits.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @returns Raw bytes representation of `packed`.
 */
export const packed2bytes = (
  packed: Array<number>,
  outputLength: number,
  bigEndianMod: customTypes.BigEndianMod,
): string => {
  let str = "";

  const length = outputLength / 8;
  const shiftModifier = bigEndianMod === -1 ? 3 : 0;

  for (let i = 0; i < length; i += 1) {
    const srcByte = (packed[i >>> 2] >>> (8 * (shiftModifier + (bigEndianMod * (i % 4))))) & 0xff;
    str += String.fromCharCode(srcByte);
  }
  return str;
};

/**
 * Convert an array of words to an ArrayBuffer.
 *
 * @param packed - Array of integers to be converted.
 * @param outputLength - Length of output in bits.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @returns An ArrayBuffer containing bytes from `packed`.
 */
export const packed2arraybuffer = (
  packed: Array<number>,
  outputLength: number,
  bigEndianMod: customTypes.BigEndianMod,
): ArrayBuffer => {
  const length = outputLength / 8;
  const retVal = new ArrayBuffer(length);
  const arrView = new Uint8Array(retVal);
  const shiftModifier = bigEndianMod === -1 ? 3 : 0;

  for (let i = 0; i < length; i += 1) {
    arrView[i] = (packed[i >>> 2] >>> (8 * (shiftModifier + (bigEndianMod * (i % 4))))) & 0xff;
  }

  return retVal;
};

/**
 * Convert an array of words to an Uint8Array.
 *
 * @param packed - Array of integers to be converted.
 * @param outputLength - Length of output in bits.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @returns An Uint8Array containing bytes from `packed`.
 */
export const packed2uint8array = (
  packed: Array<number>,
  outputLength: number,
  bigEndianMod: customTypes.BigEndianMod,
): Uint8Array => {
  const length = outputLength / 8;
  const shiftModifier = bigEndianMod === -1 ? 3 : 0;
  const retVal = new Uint8Array(length);

  for (let i = 0; i < length; i += 1) {
    retVal[i] = (packed[i >>> 2] >>> (8 * (shiftModifier + (bigEndianMod * (i % 4))))) & 0xff;
  }

  return retVal;
};

/**
 * Function that takes an output format and associated parameters and returns a function that
 * converts packed integers to that format.
 *
 * @param format - The desired output formatting.
 * @param outputBinLen - Output length in bits.
 * @param bigEndianMod - Modifier for whether hash function is big or small endian.
 * @param outputOptions - Hashmap of output formatting options
 * @returns Function that will convert a packed integer array to desired format.
 */
export function getOutputConverter(
  format: customTypes.FormatType.hex
  | customTypes.FormatType.b64
  | customTypes.FormatType.bytes,
  outputBinLen: number,
  bigEndianMod: customTypes.BigEndianMod,
  outputOptions: { outputUpper: boolean; b64Pad: string }
): (binarray: Array<number>) => string;
export function getOutputConverter(
  format: customTypes.FormatType.arrayBuffer,
  outputBinLen: number,
  bigEndianMod: customTypes.BigEndianMod,
  outputOptions: { outputUpper: boolean; b64Pad: string }
): (binarray: Array<number>) => ArrayBuffer;
export function getOutputConverter(
  format: customTypes.FormatType.uint8Array,
  outputBinLen: number,
  bigEndianMod: customTypes.BigEndianMod,
  outputOptions: { outputUpper: boolean; b64Pad: string }
): (binarray: Array<number>) => Uint8Array;
// eslint-disable-next-line func-style
export function getOutputConverter(
  format: customTypes.FormatNoTextType,
  outputBinLen: number,
  bigEndianMod: customTypes.BigEndianMod,
  outputOptions: {outputUpper: boolean; b64Pad: string},
): unknown {
  switch (format) {
  case customTypes.FormatType.hex:
    return (
      binarray: Array<number>,
    ): string => packed2hex(binarray, outputBinLen, bigEndianMod, outputOptions);
  case customTypes.FormatType.b64:
    return (
      binarray: Array<number>,
    ): string => packed2b64(binarray, outputBinLen, bigEndianMod, outputOptions);
  case customTypes.FormatType.bytes:
    return (
      binarray: Array<number>,
    ): string => packed2bytes(binarray, outputBinLen, bigEndianMod);
  case customTypes.FormatType.arrayBuffer:
    return (
      binarray: Array<number>,
    ): ArrayBuffer => packed2arraybuffer(binarray, outputBinLen, bigEndianMod);
  case customTypes.FormatType.uint8Array:
    return (
      binarray: Array<number>,
    ): Uint8Array => packed2uint8array(binarray, outputBinLen, bigEndianMod);
  default:
    throw new Error("format must be HEX, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY");
  }
}
