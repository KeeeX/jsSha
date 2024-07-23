/* eslint-disable @typescript-eslint/no-magic-numbers */
export enum EncodingType {
  utf16BE = "UTF16BE",
  utf16LE = "UTF16LE",
  utf8 = "UTF8",
}
Object.freeze(EncodingType);

export enum FormatType {
  arrayBuffer = "ARRAYBUFFER",
  b64 = "B64",
  bytes = "BYTES",
  hex = "HEX",
  text = "TEXT",
  uint8Array = "UINT8ARRAY",
}
Object.freeze(FormatType);

export type FormatNoTextType =
| FormatType.arrayBuffer
| FormatType.b64
| FormatType.bytes
| FormatType.hex
| FormatType.uint8Array;

interface InputTypeText {
  value: string;
  format: FormatType.text;
  encoding?: EncodingType;
}

interface InputTypeBinaryString {
  value: string;
  format: FormatType.b64 | FormatType.hex | FormatType.bytes;
}

interface InputTypeArrayBuffer {
  value: ArrayBuffer;
  format: FormatType.arrayBuffer;
}

interface InputTypeUint8Array {
  value: Uint8Array;
  format: FormatType.uint8Array;
}

export type GenericInputType =
| InputTypeText
| InputTypeBinaryString
| InputTypeArrayBuffer
| InputTypeUint8Array;

interface FLOptsNoEncTypeHmac {
  hmacKey?: GenericInputType;
}

interface FLOptsNoEncTypeRounds {
  numRounds?: number;
}

export type FixedLengthOptionsNoEncodingType =
| FLOptsNoEncTypeHmac
| FLOptsNoEncTypeRounds;

interface OptsEncType {
  encoding?: EncodingType;
}

export type FixedLengthOptionsEncodingType = FixedLengthOptionsNoEncodingType & OptsEncType;

export interface PackedValue {
  value: Array<number>;
  binLen: number;
}

export interface SHAKEOptionsNoEncodingType {
  numRounds?: number;
}

export interface SHAKEOptionsEncodingType extends SHAKEOptionsNoEncodingType {
  encoding?: EncodingType;
}

export interface CSHAKEOptionsNoEncodingType {
  customization?: GenericInputType;
  funcName?: GenericInputType;
}

export interface CSHAKEOptionsEncodingType extends CSHAKEOptionsNoEncodingType {
  encoding?: EncodingType;
}

export interface KMACOptionsNoEncodingType {
  kmacKey: GenericInputType;
  customization?: GenericInputType;
  funcName?: GenericInputType;
}

export interface KMACOptionsEncodingType extends KMACOptionsNoEncodingType {
  encoding?: EncodingType;
}

export interface ResolvedCSHAKEOptionsNoEncodingType {
  funcName: PackedValue;
  customization: PackedValue;
}

export interface ResolvedKMACOptionsNoEncodingType extends ResolvedCSHAKEOptionsNoEncodingType {
  kmacKey: PackedValue;
}

export type RoundFunc<StateT> = (block: Array<number>, H: StateT) => StateT;

export type FinalizeFunc<StateT> = (
  remainder: Array<number>,
  remainderBinLen: number,
  processedBinLen: number,
  H: StateT,
  outputLen: number
) => Array<number>;

export type StateCloneFunc<StateT> = (state: StateT) => StateT;

export type NewStateFunc<StateT, VariantT> = (variant: VariantT) => StateT;

export type GetMacFunc = (options: {outputLen: number}) => Array<number>;

export type BigEndianMod = 1 | -1;
