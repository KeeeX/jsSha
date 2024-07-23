/* eslint-disable mocha/no-setup-in-describe */
/* eslint-disable @typescript-eslint/no-magic-numbers */
import {assert} from "chai";
import * as sha256 from "../sha256.js";
import * as common from "./common.js";

const newState224 = [
  0xc1059ed8,
  0x367cd507,
  0x3070dd17,
  0xf70e5939,
  0xffc00b31,
  0x68581511,
  0x64f98fa7,
  0xbefa4fa4,
];
const newState256 = [
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
];
const abcPostProcessed = [0x61626380, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000018];

describe("sha256", () => {
  describe("Test getNewState256", () => {
    const getNewState = sha256.getNewState256;

    it("For SHA-224", () => {
      assert.deepEqual(getNewState(sha256.Sha256VariantType.sha224), newState224);
    });

    it("For SHA-256", () => {
      assert.deepEqual(getNewState(sha256.Sha256VariantType.sha256), newState256);
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

  common.runHashTests(sha256.Sha256VariantType.sha224, sha256.JsSha256 as common.JsShaCtor);
  common.runHashTests(sha256.Sha256VariantType.sha256, sha256.JsSha256 as common.JsShaCtor);
});
