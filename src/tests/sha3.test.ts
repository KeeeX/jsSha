/* eslint-disable max-lines-per-function */
/* eslint-disable @typescript-eslint/no-magic-numbers */
/* eslint-disable mocha/no-setup-in-describe */
import {assert} from "chai";
import {Int64} from "../primitives_64.js";
import * as sha3 from "../sha3.js";
import {FormatType} from "../custom_types.js";
import * as sha3Consts from "./sha3_consts.js";
import {JsShaCtor, runHashTests} from "./common.js";

const getNewState = sha3.getNewState;

describe("sha3", () => {
  describe("Test left_encode", () => {
    const leftEncode = sha3.leftEncode;

    it("For 0-byte Value", () => {
      assert.deepEqual(leftEncode(0), {value: [0x00000001], binLen: 16});
    });

    it("For 1-byte Value", () => {
      assert.deepEqual(leftEncode(0x11), {value: [0x000001101], binLen: 16});
    });

    it("For 2-byte Value", () => {
      assert.deepEqual(leftEncode(0x1122), {value: [0x000221102], binLen: 24});
    });

    it("For 3-byte Value", () => {
      assert.deepEqual(leftEncode(0x112233), {value: [0x33221103], binLen: 32});
    });

    it("For 4-byte Value", () => {
      assert.deepEqual(leftEncode(0x11223344), {value: [0x33221104, 0x00000044], binLen: 40});
    });

    it("For 7-byte Value", () => {
      /* 4822678189205111 === 0x0011223344556677 */
      assert.deepEqual(
        leftEncode(4822678189205111),
        {value: [0x33221107 | 0, 0x77665544 | 0], binLen: 64},
      );
    });
  });

  describe("Test right_encode", () => {
    const rightEncode = sha3.rightEncode;

    it("For 0-byte Value", () => {
      assert.deepEqual(rightEncode(0), {value: [0x00000100], binLen: 16});
    });

    it("For 1-byte Value", () => {
      assert.deepEqual(rightEncode(0x11), {value: [0x000000111], binLen: 16});
    });

    it("For 2-byte Value", () => {
      assert.deepEqual(rightEncode(0x1122), {value: [0x00022211], binLen: 24});
    });

    it("For 3-byte Value", () => {
      assert.deepEqual(rightEncode(0x112233), {value: [0x03332211], binLen: 32});
    });

    it("For 4-byte Value", () => {
      assert.deepEqual(rightEncode(0x11223344), {value: [0x44332211, 0x00000004], binLen: 40});
    });

    it("For 7-byte Value", () => {
      /* 4822678189205111 === 0x0011223344556677 */
      assert.deepEqual(
        rightEncode(4822678189205111),
        {value: [0x44332211 | 0, 0x07776655], binLen: 64},
      );
    });
  });

  describe("Test encode_string", () => {
    const encodeString = sha3.encodeString;

    it("For 0-bit Input", () => {
      assert.deepEqual(encodeString({value: [], binLen: 0}), {value: [0x00000001], binLen: 16});
    });

    it("For 16-bit Input", () => {
      /* This checks values that can be encoded in a single int */
      assert.deepEqual(
        encodeString({value: [0x1122], binLen: 16}),
        {value: [0x11221001], binLen: 32},
      );
    });

    it("For 24-bit Input", () => {
      /* This checks values that can be encoded in 2 ints (and left_encode returns a 16-bit value) */
      assert.deepEqual(
        encodeString({value: [0x112233], binLen: 24}),
        {value: [0x22331801, 0x00000011], binLen: 40},
      );
    });

    it("For 256-bit Input", () => {
      /* This hits on the case that left_encode returns a 24-bit value */
      const arr = [];
      const retVal = [0x41000102];
      for (let i = 0; i < 8; i++) arr.push(0x41414141);
      for (let i = 0; i < 7; i++) retVal.push(0x41414141);
      retVal.push(0x00414141);
      assert.deepEqual(encodeString({value: arr, binLen: 256}), {value: retVal, binLen: 280});
    });

    it("For 65536-bit Input", () => {
      /* This hits on the case that left_encode returns a 32-bit value */
      const arr = [];
      for (let i = 0; i < 2048; i++) arr.push(0x41414141);
      assert.deepEqual(
        encodeString({value: arr, binLen: 65536}),
        {value: [0x00000103].concat(arr), binLen: 65568},
      );
    });

    it("For 16777216-bit Input", () => {
      /* This hits on the case that left_encode returns a 40-bit value */
      const arr = [];
      for (let i = 0; i < 524288; i++) arr.push(0x41414141);
      const retVal = encodeString({value: arr, binLen: 16777216});

      /* It's extremely time prohibitive to check all the middle bits so just check the interesting ends */
      assert.equal(retVal["value"][0], 0x00000104);
      assert.equal(retVal["value"][1], 0x41414100);
      assert.equal(retVal["value"].length, 524288 + 2);
      assert.equal(retVal["value"][retVal["value"].length - 1], 0x00000041);
      assert.equal(retVal["binLen"], 16777256);
    });
  });

  describe("Test byte_pad", () => {
    const bytePad = sha3.bytePad;

    it("For 2-byte Value Padded to 4-bytes", () => {
      assert.deepEqual(bytePad({value: [0x00001122], binLen: 16}, 4), [0x11220401]);
    });

    it("For 2-byte Value Padded to 8-bytes", () => {
      assert.deepEqual(bytePad({value: [0x00001122], binLen: 16}, 8), [0x11220801, 0]);
    });

    it("For 4-byte Value Padded to 8-bytes", () => {
      assert.deepEqual(bytePad({value: [0x11223344], binLen: 32}, 8), [0x33440801, 0x00001122]);
    });

    it("For 6-byte Value Padded to 8-bytes", () => {
      assert.deepEqual(
        bytePad({value: [0x44332211, 0x00006655], binLen: 48}, 8),
        [0x22110801, 0x66554433],
      );
    });
  });

  describe("Test resolveCSHAKEOptions", () => {
    const resolveCSHAKEOptions = sha3.resolveCSHAKEOptions;

    it("With No Input", () => {
      assert.deepEqual(resolveCSHAKEOptions(), {
        funcName: {value: [], binLen: 0},
        customization: {value: [], binLen: 0},
      });
    });

    it("With customization Specified", () => {
      assert.deepEqual(resolveCSHAKEOptions({customization: {value: "00112233", format: FormatType.hex}}), {
        funcName: {value: [], binLen: 0},
        customization: {value: [0x33221100], binLen: 32},
      });
    });

    it("With funcName Specified", () => {
      assert.deepEqual(resolveCSHAKEOptions({funcName: {value: "00112233", format: FormatType.hex}}), {
        customization: {value: [], binLen: 0},
        funcName: {value: [0x33221100], binLen: 32},
      });
    });
  });

  describe("Test resolveKMACOptions", () => {
    const resolveKMACOptions = sha3.resolveKMACOptions;

    it("With No Input", () => {
      assert.throws(() => {
        resolveKMACOptions();
      }, "kmacKey must include a value and format");
    });

    it("With customization Specified", () => {
      assert.deepEqual(
        resolveKMACOptions({
          kmacKey: {value: "44556677", format: FormatType.hex},
          customization: {value: "00112233", format: FormatType.hex},
        }),
        {
          funcName: {value: [0x43414d4b], binLen: 32},
          customization: {value: [0x33221100], binLen: 32},
          kmacKey: {value: [0x77665544], binLen: 32},
        },
      );
    });

    it("With funcName Specified", () => {
      assert.deepEqual(
        resolveKMACOptions({
          kmacKey: {value: "44556677", format: FormatType.hex},
          funcName: {value: "00112233", format: FormatType.hex},
        }),
        {
          funcName: {value: [0x43414d4b], binLen: 32},
          customization: {value: [], binLen: 0},
          kmacKey: {value: [0x77665544], binLen: 32},
        },
      );
    });
  });

  describe("Test getNewState", () => {
    it("For All Variants", () => {
      assert.deepEqual(getNewState(), sha3Consts.newState);
    });
  });

  describe("Test cloneSHA3State", () => {
    const cloneSHA3State = sha3.cloneSHA3State;

    const state = [
      [new Int64(0, 1), new Int64(0, 2), new Int64(0, 3), new Int64(0, 4), new Int64(0, 5)],
      [new Int64(0, 6), new Int64(0, 7), new Int64(0, 8), new Int64(0, 9), new Int64(0, 0xa)],
      [
        new Int64(0, 0xb),
        new Int64(0, 0xc),
        new Int64(0, 0xd),
        new Int64(0, 0xb),
        new Int64(0, 0xf),
      ],
      [
        new Int64(0, 0x10),
        new Int64(0, 0x11),
        new Int64(0, 0x12),
        new Int64(0, 0x3),
        new Int64(0, 0x14),
      ],
      [
        new Int64(0, 0x15),
        new Int64(0, 0x16),
        new Int64(0, 0x17),
        new Int64(0, 0x18),
        new Int64(0, 0x19),
      ],
    ];

    it("For All Variants", () => {
      assert.notEqual(cloneSHA3State(state), state);
      assert.deepEqual(cloneSHA3State(state), state);
    });
  });

  describe("Test roundSHA3", () => {
    it("With NIST Test Inputs", () => {
      assert.deepEqual(
        sha3.roundSHA3(sha3Consts.nistSha3Round1In.slice(), getNewState()),
        sha3Consts.nistSha3Round1Out,
      );
    });
  });

  runHashTests(sha3.Sha3VariantType.sha3224, sha3.JsSHA3 as JsShaCtor);
  runHashTests(sha3.Sha3VariantType.sha3256, sha3.JsSHA3 as JsShaCtor);
  runHashTests(sha3.Sha3VariantType.sha3384, sha3.JsSHA3 as JsShaCtor);
  runHashTests(sha3.Sha3VariantType.sha3512, sha3.JsSHA3 as JsShaCtor);
  runHashTests(sha3.Sha3VariantType.shake128, sha3.JsSHA3 as JsShaCtor);
  runHashTests(sha3.Sha3VariantType.shake256, sha3.JsSHA3 as JsShaCtor);
  runHashTests(sha3.Sha3VariantType.cshake128, sha3.JsSHA3 as JsShaCtor);
  runHashTests(sha3.Sha3VariantType.cshake256, sha3.JsSHA3 as JsShaCtor);
  runHashTests(sha3.Sha3VariantType.kmac128, sha3.JsSHA3 as JsShaCtor);
  runHashTests(sha3.Sha3VariantType.kmac256, sha3.JsSHA3 as JsShaCtor);
});
