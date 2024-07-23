/* eslint-disable mocha/no-setup-in-describe */
/* eslint-disable @typescript-eslint/no-magic-numbers */
import {assert} from "chai";
import {Int64} from "../primitives_64.js";
import * as sha512 from "../sha512.js";
import * as common from "./common.js";

const hTrunc = [
  0xc1059ed8,
  0x367cd507,
  0x3070dd17,
  0xf70e5939,
  0xffc00b31,
  0x68581511,
  0x64f98fa7,
  0xbefa4fa4,
];

const hFull = [
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
];

const newState384 = [
  new Int64(0xcbbb9d5d, hTrunc[0]),
  new Int64(0x0629a292a, hTrunc[1]),
  new Int64(0x9159015a, hTrunc[2]),
  new Int64(0x0152fecd8, hTrunc[3]),
  new Int64(0x67332667, hTrunc[4]),
  new Int64(0x98eb44a87, hTrunc[5]),
  new Int64(0xdb0c2e0d, hTrunc[6]),
  new Int64(0x047b5481d, hTrunc[7]),
];
const newState512 = [
  new Int64(hFull[0], 0xf3bcc908),
  new Int64(hFull[1], 0x84caa73b),
  new Int64(hFull[2], 0xfe94f82b),
  new Int64(hFull[3], 0x5f1d36f1),
  new Int64(hFull[4], 0xade682d1),
  new Int64(hFull[5], 0x2b3e6c1f),
  new Int64(hFull[6], 0xfb41bd6b),
  new Int64(hFull[7], 0x137e2179),
];
const abcPostProcessed = [
  0x61626380,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0x00000018,
];

describe("SHA512", () => {
  describe("Test getNewState512", () => {
    const getNewState = sha512.getNewState512;

    it("For SHA-384", () => {
      assert.deepEqual(getNewState(sha512.Sha512VariantType.sha384), newState384);
    });

    it("For SHA-512", () => {
      assert.deepEqual(getNewState(sha512.Sha512VariantType.sha512), newState512);
    });
  });

  describe("Test roundSHA512", () => {
    const roundSHA512 = sha512.roundSHA512;

    it("SHA-384 With NIST Test Inputs", () => {
      assert.deepEqual(roundSHA512(abcPostProcessed, newState384.slice()), [
        new Int64(0xcb00753f | 0, 0x45a35e8b | 0),
        new Int64(0xb5a03d69 | 0, 0x9ac65007 | 0),
        new Int64(0x272c32ab | 0, 0x0eded163 | 0),
        new Int64(0x1a8b605a | 0, 0x43ff5bed | 0),
        new Int64(0x8086072b | 0, 0xa1e7cc23 | 0),
        new Int64(0x58baeca1 | 0, 0x34c825a7 | 0),
        new Int64(0xa303edfd | 0, 0xf3b89cd7 | 0),
        new Int64(0x0c66918e | 0, 0xce57ba15 | 0),
      ]);
    });

    it("SHA-512 With NIST Test Inputs", () => {
      assert.deepEqual(roundSHA512(abcPostProcessed, newState512.slice()), [
        new Int64(0xddaf35a1 | 0, 0x93617aba | 0),
        new Int64(0xcc417349 | 0, 0xae204131 | 0),
        new Int64(0x12e6fa4e | 0, 0x89a97ea2 | 0),
        new Int64(0x0a9eeee6 | 0, 0x4b55d39a | 0),
        new Int64(0x2192992a | 0, 0x274fc1a8 | 0),
        new Int64(0x36ba3c23 | 0, 0xa3feebbd | 0),
        new Int64(0x454d4423 | 0, 0x643ce80e | 0),
        new Int64(0x2a9ac94f | 0, 0xa54ca49f | 0),
      ]);
    });
  });

  common.runHashTests(sha512.Sha512VariantType.sha384, sha512.JsSha512 as common.JsShaCtor);
  common.runHashTests(sha512.Sha512VariantType.sha512, sha512.JsSha512 as common.JsShaCtor);
});
