import * as common from "./common.js";
import * as customTypes from "./custom_types.js";
import * as sha1 from "./sha1.js";
import * as sha256 from "./sha256.js";
import * as sha512 from "./sha512.js";
import * as sha3 from "./sha3.js";

export type FixedLengthVariantType =
  | sha1.Sha1VariantType.sha1
  | sha256.Sha256VariantType.sha224
  | sha256.Sha256VariantType.sha256
  | sha512.Sha512VariantType.sha384
  | sha512.Sha512VariantType.sha512
  | sha3.Sha3VariantType.sha3224
  | sha3.Sha3VariantType.sha3256
  | sha3.Sha3VariantType.sha3384
  | sha3.Sha3VariantType.sha3512;

export type AllVariantType =
  | sha1.Sha1VariantType.sha1
  | sha256.Sha256VariantType.sha224
  | sha256.Sha256VariantType.sha256
  | sha512.Sha512VariantType.sha384
  | sha512.Sha512VariantType.sha512
  | sha3.Sha3VariantType.sha3224
  | sha3.Sha3VariantType.sha3256
  | sha3.Sha3VariantType.sha3384
  | sha3.Sha3VariantType.sha3512
  | sha3.Sha3VariantType.shake128
  | sha3.Sha3VariantType.shake256
  | sha3.Sha3VariantType.cshake128
  | sha3.Sha3VariantType.cshake256
  | sha3.Sha3VariantType.kmac128
  | sha3.Sha3VariantType.kmac256;

export default class JsSha {
  readonly #shaObj: sha1.JsSha1 | sha256.JsSha256 | sha512.JsSha512 | sha3.JsSHA3;
  /**
   * @param variant - The desired SHA variant (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224,
   * SHA3-256, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, CSHAKE128, CSHAKE256, KMAC128, or
   * KMAC256) as a string.
   * @param inputFormat - The input format to be used in future `update` calls (TEXT, HEX, B64,
   * BYTES, ARRAYBUFFER, or UINT8ARRAY) as a string.
   * @param options - Options in the form of
   * \{ encoding?: "UTF8" | "UTF16BE" | "UTF16LE"; numRounds?: number \}.
   *   `encoding` is for only TEXT input (defaults to UTF8) and `numRounds` defaults to 1.
   *   `numRounds` is not valid for any of the MAC or CSHAKE variants.
   *   * If the variant supports HMAC, `options` may have an additional `hmacKey` key which must be
   *     in the form of
   *     \{value: <INPUT>, format: <FORMAT>, encoding?: "UTF8" | "UTF16BE" | "UTF16LE"\} where
   *     <FORMAT> takes the same
   *     values as `inputFormat` and <INPUT> can be a `string | ArrayBuffer | Uint8Array` depending
   *     on <FORMAT>.
   *     Supplying this key switches to HMAC calculation and replaces the now deprecated call to
   *     `setHMACKey`.
   *   * If the variant is CSHAKE128 or CSHAKE256, `options` may have two additional keys,
   *     `customization` and `funcName`, which are the NIST customization and function-name strings.
   *     Both must be in the same form as `hmacKey`.
   *   * If the variant is KMAC128 or KMAC256, `options` can include the `customization` key from
   *     CSHAKE variants and *must* have a `kmacKey` key that takes the same form as the
   *     `customization` key.
   */
  public constructor(
    variant: FixedLengthVariantType,
    inputFormat: customTypes.FormatType.text,
    options?: customTypes.FixedLengthOptionsEncodingType,
  );

  public constructor(
    variant: FixedLengthVariantType,
    inputFormat: customTypes.FormatNoTextType,
    options?: customTypes.FixedLengthOptionsNoEncodingType,
  );

  public constructor(
    variant: sha3.Sha3VariantType.shake128 | sha3.Sha3VariantType.shake256,
    inputFormat: customTypes.FormatType.text,
    options?: customTypes.SHAKEOptionsEncodingType,
  );

  public constructor(
    variant: sha3.Sha3VariantType.shake128 | sha3.Sha3VariantType.shake256,
    inputFormat: customTypes.FormatNoTextType,
    options?: customTypes.SHAKEOptionsNoEncodingType,
  );

  public constructor(
    variant: sha3.Sha3VariantType.cshake128 | sha3.Sha3VariantType.cshake256,
    inputFormat: customTypes.FormatType.text,
    options?: customTypes.CSHAKEOptionsEncodingType,
  );

  public constructor(
    variant: sha3.Sha3VariantType.cshake128 | sha3.Sha3VariantType.cshake256,
    inputFormat: customTypes.FormatNoTextType,
    options?: customTypes.CSHAKEOptionsNoEncodingType,
  );

  public constructor(
    variant: sha3.Sha3VariantType.kmac128 | sha3.Sha3VariantType.kmac256,
    inputFormat: customTypes.FormatType.text,
    options: customTypes.KMACOptionsEncodingType,
  );

  public constructor(
    variant: sha3.Sha3VariantType.kmac128 | sha3.Sha3VariantType.kmac256,
    inputFormat: customTypes.FormatNoTextType,
    options: customTypes.KMACOptionsNoEncodingType,
  );

  public constructor(
    variant: AllVariantType,
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
    if (sha1.Sha1VariantType.sha1 === variant) {
      this.#shaObj = new sha1.JsSha1(
        variant,
        inputFormat as customTypes.FormatNoTextType,
        options as customTypes.FixedLengthOptionsNoEncodingType,
      );
    } else if (
      sha256.Sha256VariantType.sha224 === variant
      || sha256.Sha256VariantType.sha256 === variant
    ) {
      this.#shaObj = new sha256.JsSha256(
        variant,
        inputFormat as customTypes.FormatNoTextType,
        options as customTypes.FixedLengthOptionsNoEncodingType,
      );
    } else if (
      sha512.Sha512VariantType.sha384 === variant
      || sha512.Sha512VariantType.sha512 === variant
    ) {
      this.#shaObj = new sha512.JsSha512(
        variant,
        inputFormat as customTypes.FormatNoTextType,
        options as customTypes.FixedLengthOptionsEncodingType,
      );
    } else {
      this.#shaObj = new sha3.JsSHA3(
        variant as sha3.Sha3FixedLengthVariantType,
        inputFormat as customTypes.FormatNoTextType,
        options as customTypes.FixedLengthOptionsNoEncodingType,
      );
    }
  }

  /**
   * Takes `input` and hashes as many blocks as possible. Stores the rest for either a future
   * `update` or `getHash` call.
   *
   * @param input - The input to be hashed.
   * @returns A reference to the object.
   */
  public update = (input: string | ArrayBuffer | Uint8Array): this => {
    this.#shaObj.update(input);
    return this;
  };

  /**
   * Returns the desired SHA or MAC (if a HMAC/KMAC key was specified) hash of the input fed in via
   * `update` calls.
   *
   * @param format - The desired output formatting (B64, HEX, BYTES, ARRAYBUFFER, or UINT8ARRAY) as
   * a string.
   * @param options - Options in the form of
   * \{ outputUpper?: boolean; b64Pad?: string; outputLen?: number;  \}.
   *   `outputLen` is required for variable length output variants (this option was previously
   *   called `shakeLen` which is now deprecated).
   *   `outputUpper` is only for HEX output (defaults to false) and b64pad is only for B64 output
   *   (defaults to "=").
   * @returns The hash in the format specified.
   */
  public getHash(
    format: customTypes.FormatType.hex,
    options?: common.GetHashOptionsHex,
  ): string;

  public getHash(
    format: customTypes.FormatType.b64,
    options?: common.GetHashOptionsB64,
  ): string;

  public getHash(
    format: customTypes.FormatType.bytes,
    options?: common.GetHashOptionsBinary,
  ): string;

  public getHash(
    format: customTypes.FormatType.uint8Array,
    options?: common.GetHashOptionsBinary,
  ): Uint8Array;

  public getHash(
    format: customTypes.FormatType.arrayBuffer,
    options?: common.GetHashOptionsBinary,
  ): ArrayBuffer;

  public getHash(
    format: customTypes.FormatNoTextType,
    options?: common.GetHashOptions,
  ): unknown {
    return this.#shaObj.getHash(
      format as customTypes.FormatType.hex,
      options as common.GetHashOptionsHex,
    );
  }

  /**
   * Sets the HMAC key for an eventual `getHMAC` call.  Must be called immediately after jsSHA
   * object instantiation.
   * Now deprecated in favor of setting the `hmacKey` at object instantiation.
   *
   * @param key - The key used to calculate the HMAC
   * @param inputFormat - The format of key (HEX, TEXT, B64, BYTES, ARRAYBUFFER, or UINT8ARRAY) as a
   * string.
   * @param options - Options in the form of \{ encoding?: "UTF8" | "UTF16BE" | "UTF16LE \}.
   * `encoding` is only for TEXT and defaults to UTF8.
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
    this.#shaObj.setHMACKey(
      key as string,
      inputFormat as customTypes.FormatType.text,
      options,
    );
  }

  /**
   * Returns the the HMAC in the specified format using the key given by a previous `setHMACKey`
   * call. Now deprecated in favor of just calling `getHash`.
   *
   * @param format - The desired output formatting (B64, HEX, BYTES, ARRAYBUFFER, or UINT8ARRAY) as
   * a string.
   * @param options - Options in the form of \{ outputUpper?: boolean; b64Pad?: string \}.
   * `outputUpper` is only for HEX
   *   output (defaults to false) and `b64pad` is only for B64 output (defaults to "=").
   * @returns The HMAC in the format specified.
   */
  public getHMAC(format: customTypes.FormatType.hex, options?: common.GetHmacOptionsHex): string;

  public getHMAC(format: customTypes.FormatType.b64, options?: common.GetHmacOptionsB64): string;

  public getHMAC(format: customTypes.FormatType.bytes): string;

  public getHMAC(format: customTypes.FormatType.uint8Array): Uint8Array;

  public getHMAC(format: customTypes.FormatType.arrayBuffer): ArrayBuffer;

  public getHMAC(format: customTypes.FormatNoTextType, options?: common.GetHmacOptions): unknown {
    return this.#shaObj.getHMAC(
      format as customTypes.FormatType.hex,
      options as common.GetHmacOptionsHex,
    );
  }
}
