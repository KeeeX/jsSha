/* eslint-disable mocha/no-setup-in-describe */
/* eslint-disable mocha/no-exports */
/* eslint-disable @typescript-eslint/no-magic-numbers */
import {assert} from "chai";
import {JsSHABase} from "../common.js";
import {AllVariantType} from "../sha.js";
import * as hashDataSrv from "./data/hash_data.js";

// eslint-disable-next-line @typescript-eslint/no-type-alias
export type JsShaCtor = new (
  variant: AllVariantType,
  format: string,
  options?: {
    numRounds?: number;
    customization?: hashDataSrv.TestTextCustomization;
    kmacKey?: hashDataSrv.TestHexKey;
    hmacKey?: hashDataSrv.TestHexKey;
  },
) => JsSHABase<unknown, unknown>;

// eslint-disable-next-line mocha/no-exports
export const runHashTests = (variant: AllVariantType, jsSha: JsShaCtor): void => {
  describe(`Test jsSHA(${variant}) Using NIST Tests`, () => {
    // eslint-disable-next-line mocha/no-setup-in-describe
    for (const test of hashDataSrv.hashData[variant]) {
      for (const output of test.outputs) {
        it(test.name, () => {
          const hashObj = new jsSha(variant, test.input.format, {
            numRounds: test.input.rounds ?? 1,
            customization: test.customization,
            kmacKey: test.kmacKey,
            hmacKey: test.hmacKey,
          });
          hashObj.update(test.input.value);
          assert.equal(
            hashObj.getHash(output.format, {outputLen: output.outputLen ?? 8}),
            output.value,
          );
        });
        break;
      }
      break;
    }
  });
};
