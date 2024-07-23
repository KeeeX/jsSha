/* eslint-disable max-lines-per-function */
/* eslint-disable mocha/no-setup-in-describe */
/* eslint-disable @typescript-eslint/no-magic-numbers */
import {assert} from "chai";
import * as sha1 from "../sha1.js";
import * as common from "./common.js";

const newState = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
const abcPostProcessed = [0x61626380, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000018];

describe("SHA1", () => {
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

  common.runHashTests(sha1.Sha1VariantType.sha1, sha1.JsSha1 as common.JsShaCtor);
});
