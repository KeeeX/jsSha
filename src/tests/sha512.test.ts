import { describe, it } from "mocha";
import { assert } from "chai";
import { runHashTests } from "./common.js";
import {
  FixedLengthOptionsEncodingType,
  FixedLengthOptionsNoEncodingType,
  FormatNoTextType,
} from "../../src/custom_types";
import { Int_64 } from "../primitives_64.js";
import * as sha512 from "../sha512.js";

const H_trunc = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
const H_full = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const newState384 = [
    new Int_64(0xcbbb9d5d, H_trunc[0]),
    new Int_64(0x0629a292a, H_trunc[1]),
    new Int_64(0x9159015a, H_trunc[2]),
    new Int_64(0x0152fecd8, H_trunc[3]),
    new Int_64(0x67332667, H_trunc[4]),
    new Int_64(0x98eb44a87, H_trunc[5]),
    new Int_64(0xdb0c2e0d, H_trunc[6]),
    new Int_64(0x047b5481d, H_trunc[7]),
  ];
const newState512 = [
    new Int_64(H_full[0], 0xf3bcc908),
    new Int_64(H_full[1], 0x84caa73b),
    new Int_64(H_full[2], 0xfe94f82b),
    new Int_64(H_full[3], 0x5f1d36f1),
    new Int_64(H_full[4], 0xade682d1),
    new Int_64(H_full[5], 0x2b3e6c1f),
    new Int_64(H_full[6], 0xfb41bd6b),
    new Int_64(H_full[7], 0x137e2179),
  ];
const abcPostProcessed = [
    0x61626380, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000018,
  ];
const abcPacked = [0x61626300];

describe("Test getNewState512", () => {
  const getNewState = sha512.getNewState512;

  it("For SHA-384", () => {
    assert.deepEqual(getNewState("SHA-384"), newState384);
  });

  it("For SHA-512", () => {
    assert.deepEqual(getNewState("SHA-512"), newState512);
  });
});

describe("Test roundSHA512", () => {
  const roundSHA512 = sha512.roundSHA512;

  it("SHA-384 With NIST Test Inputs", () => {
    assert.deepEqual(roundSHA512(abcPostProcessed, newState384.slice()), [
      new Int_64(0xcb00753f | 0, 0x45a35e8b | 0),
      new Int_64(0xb5a03d69 | 0, 0x9ac65007 | 0),
      new Int_64(0x272c32ab | 0, 0x0eded163 | 0),
      new Int_64(0x1a8b605a | 0, 0x43ff5bed | 0),
      new Int_64(0x8086072b | 0, 0xa1e7cc23 | 0),
      new Int_64(0x58baeca1 | 0, 0x34c825a7 | 0),
      new Int_64(0xa303edfd | 0, 0xf3b89cd7 | 0),
      new Int_64(0x0c66918e | 0, 0xce57ba15 | 0),
    ]);
  });

  it("SHA-512 With NIST Test Inputs", () => {
    assert.deepEqual(roundSHA512(abcPostProcessed, newState512.slice()), [
      new Int_64(0xddaf35a1 | 0, 0x93617aba | 0),
      new Int_64(0xcc417349 | 0, 0xae204131 | 0),
      new Int_64(0x12e6fa4e | 0, 0x89a97ea2 | 0),
      new Int_64(0x0a9eeee6 | 0, 0x4b55d39a | 0),
      new Int_64(0x2192992a | 0, 0x274fc1a8 | 0),
      new Int_64(0x36ba3c23 | 0, 0xa3feebbd | 0),
      new Int_64(0x454d4423 | 0, 0x643ce80e | 0),
      new Int_64(0x2a9ac94f | 0, 0xa54ca49f | 0),
    ]);
  });
});

describe("Test jsSHA(SHA-512)", () => {
  const jsSHA = sha512.jsSHA512;
  class jsSHAATest extends jsSHA {
    constructor(variant: "SHA-384" | "SHA-512", inputFormat: "TEXT", options?: FixedLengthOptionsEncodingType);
    constructor(
      variant: "SHA-384" | "SHA-512",
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
    const hash = new jsSHAATest("SHA-512", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.isTrue(hash.getter("macKeySet"));
  });

  it("With hmacKey Set at Instantiation but then also setHMACKey", () => {
    const hash = new jsSHAATest("SHA-512", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.throws(() => {
      hash.setHMACKey("TEST", "TEXT");
    }, "MAC key already set");
  });
});

runHashTests("SHA-384", sha512.jsSHA512);
runHashTests("SHA-512", sha512.jsSHA512);
