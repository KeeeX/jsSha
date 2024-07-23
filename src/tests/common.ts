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
    hashDataSrv.hashData[variant].forEach(test => {
      test.outputs.forEach(output => {
        if (test.hmacKey) {
          it(`${test.name} - Old Style`, () => {
            const hashObj = new jsSha(variant, test.input.format);
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-ignore
            hashObj.setHMACKey(test.hmacKey.value, test.hmacKey.format);
            hashObj.update(test.input.value);
            assert.equal(hashObj.getHMAC(output.format), output.value);
          });
        }
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
      });
    });
  });
};
