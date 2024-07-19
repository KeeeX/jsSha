import { describe, it } from "mocha";
import { assert } from "chai";
import {
  FixedLengthOptionsEncodingType,
  FixedLengthOptionsNoEncodingType,
  FormatNoTextType,
} from "../../src/custom_types.js";
import { runHashTests } from "./common.js";
import * as sha256 from "../sha256.js";

const newState224 = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
const newState256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const abcPostProcessed = [0x61626380, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000018];
const abcPacked = [0x61626300];

describe("Test getNewState256", () => {
  const getNewState = sha256.getNewState256;

  it("For SHA-224", () => {
    assert.deepEqual(getNewState("SHA-224"), newState224);
  });

  it("For SHA-256", () => {
    assert.deepEqual(getNewState("SHA-256"), newState256);
  });
});

describe("Test roundSHA256", () => {
  const roundSHA256 = sha256.roundSHA256;

  it("SHA-224 With NIST Test Inputs", () => {
    assert.deepEqual(roundSHA256(abcPostProcessed, newState224.slice()), [
      0x23097d22,
      0x3405d822,
      0x8642a477 | 0,
      0xbda255b3 | 0,
      0x2aadbce4,
      0xbda0b3f7 | 0,
      0xe36c9da7 | 0,
      0xd2da082d | 0,
    ]);
  });

  it("SHA-256 With NIST Test Inputs", () => {
    assert.deepEqual(roundSHA256(abcPostProcessed, newState256.slice()), [
      0xba7816bf | 0,
      0x8f01cfea | 0,
      0x414140de,
      0x5dae2223,
      0xb00361a3 | 0,
      0x96177a9c | 0,
      0xb410ff61 | 0,
      0xf20015ad | 0,
    ]);
  });
});

describe("Test jsSHA(SHA-256)", () => {
  const jsSHA = sha256.jsSHA256;
  class jsSHAATest extends jsSHA {
    constructor(variant: "SHA-224" | "SHA-256", inputFormat: "TEXT", options?: FixedLengthOptionsEncodingType);
    constructor(
      variant: "SHA-224" | "SHA-256",
      inputFormat: FormatNoTextType,
      options?: FixedLengthOptionsNoEncodingType,
    );
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    constructor(variant: any, inputFormat: any, options?: any) {
      super(variant, inputFormat, options);
    }

    /*
     * Dirty hack function to expose the protected members of jsSHABase
     */
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    getter(propName: string): any {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore - Override "any" ban as this is only used in testing
      return this[propName];
    }
  }

  it("With Invalid Variant", () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore - Deliberate bad variant value to test exceptions
    assert.throws(() => new jsSHA("SHA-TEST", "HEX"), "Chosen SHA variant is not supported");
  });

  it("With hmacKey Set at Instantiation", () => {
    const hash = new jsSHAATest("SHA-256", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.isTrue(hash.getter("macKeySet"));
  });

  it("With hmacKey Set at Instantiation but then also setHMACKey", () => {
    const hash = new jsSHAATest("SHA-256", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.throws(() => {
      hash.setHMACKey("TEST", "TEXT");
    }, "MAC key already set");
  });
});

runHashTests("SHA-224", sha256.jsSHA256);
runHashTests("SHA-256", sha256.jsSHA256);
