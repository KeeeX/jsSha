import { describe, it } from "mocha";
import { assert } from "chai";
import {
  FixedLengthOptionsEncodingType,
  FixedLengthOptionsNoEncodingType,
  FormatNoTextType,
} from "../custom_types.js";
import { runHashTests } from "./common.js";
import * as sha1 from "../sha1.js";

const newState = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
const abcPostProcessed = [0x61626380, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000018];
const abcPacked = [0x61626300];

describe("Test getNewState", () => {
  const getNewState = sha1.getNewState;

  it("With No Inputs", () => {
    assert.deepEqual(getNewState(), newState);
  });
});

describe("Test roundSHA1", () => {
  const roundSHA1 = sha1.roundSHA1;

  it("With NIST Test Inputs", () => {
    assert.deepEqual(roundSHA1(abcPostProcessed, newState.slice()), [
      0xa9993e36 | 0,
      0x4706816a,
      0xba3e2571 | 0,
      0x7850c26c,
      0x9cd0d89d | 0,
    ]);
  });
});

describe("Test jsSHA(SHA-1)", () => {
  const jsSHA = sha1.jsSHA1;

  class jsSHAATest extends jsSHA {
    constructor(variant: "SHA-1", inputFormat: "TEXT", options?: FixedLengthOptionsEncodingType);
    constructor(variant: "SHA-1", inputFormat: FormatNoTextType, options?: FixedLengthOptionsNoEncodingType);
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
    const hash = new jsSHAATest("SHA-1", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.isTrue(hash.getter("macKeySet"));
  });

  it("With hmacKey Set at Instantiation but then also setHMACKey", () => {
    const hash = new jsSHAATest("SHA-1", "HEX", { hmacKey: { value: "TEST", format: "TEXT" } });
    assert.throws(() => {
      hash.setHMACKey("TEST", "TEXT");
    }, "MAC key already set");
  });
});

runHashTests("SHA-1", sha1.jsSHA1);
