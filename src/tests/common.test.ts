/* eslint-disable max-lines-per-function */
/* eslint-disable @typescript-eslint/no-magic-numbers */
import {assert} from "chai";
import * as common from "../common.js";
import {FormatType} from "../custom_types.js";

describe("common.ts", () => {
  describe("Test packedLEConcat", () => {
    it("For 2 0-byte Values", () => {
      assert.deepEqual(
        common.packedLEConcat({value: [], binLen: 0}, {value: [], binLen: 0}),
        {value: [], binLen: 0},
      );
    });

    it("For 2 3-byte Values", () => {
      assert.deepEqual(
        common.packedLEConcat({value: [0x00112233], binLen: 24}, {value: [0x00aabbcc], binLen: 24}),
        {value: [0xcc112233 | 0, 0x0000aabb], binLen: 48},
      );
    });

    it("For 2 4-byte Values", () => {
      assert.deepEqual(
        common.packedLEConcat({value: [0x11223344], binLen: 32}, {value: [0xaabbccdd], binLen: 32}),
        {value: [0x11223344, 0xaabbccdd], binLen: 64},
      );
    });

    it("For 1 1-byte and 1 3-byte Value", () => {
      assert.deepEqual(
        common.packedLEConcat({value: [0x00000011], binLen: 8}, {value: [0x00aabbcc], binLen: 24}),
        {value: [0xaabbcc11 | 0], binLen: 32},
      );
    });
  });

  describe("Test parseInputOption", () => {
    it("For Fully Specified Value", () => {
      assert.deepEqual(
        common.parseInputOption("kmacKey", {value: "00112233", format: FormatType.hex}, 1),
        {value: [0x33221100], binLen: 32},
      );
    });

    it("For Empty but Optional Value", () => {
      assert.deepEqual(
        common.parseInputOption("kmacKey", undefined, 1, {value: [], binLen: 0}),
        {value: [], binLen: 0},
      );
    });

    it("For Empty but Required Value", () => {
      assert.throws(
        () => {
          common.parseInputOption("kmacKey", undefined, 1);
        },
        "kmacKey must include a value and format",
      );
    });
  });

  describe("Test getOutputOpts", () => {
    it("Empty Input", () => {
      assert.deepEqual(common.getOutputOpts(), {outputUpper: false, b64Pad: "=", outputLen: -1});
    });

    it("b64Pad Specified", () => {
      assert.deepEqual(
        common.getOutputOpts({b64Pad: "#"}),
        {outputUpper: false, b64Pad: "#", outputLen: -1},
      );
    });

    it("outputLen Specified", () => {
      assert.deepEqual(
        common.getOutputOpts({outputLen: 16, shakeLen: 8}),
        {outputUpper: false, b64Pad: "=", outputLen: 16},
      );
    });

    it("shakeLen Specified", () => {
      assert.deepEqual(
        common.getOutputOpts({shakeLen: 8}),
        {outputUpper: false, b64Pad: "=", outputLen: 8},
      );
    });

    it("Invalid shakeLen", () => {
      assert.throws(
        () => {
          common.getOutputOpts({shakeLen: 1});
        },
        "Output length must be a multiple of 8",
      );
    });

    it("Invalid outputLen", () => {
      assert.throws(
        () => {
          common.getOutputOpts({outputLen: 1});
        },
        "Output length must be a multiple of 8",
      );
    });
  });
});
