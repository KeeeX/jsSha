import {assert} from "chai";
import JsSha from "../sha.js";
import {Sha1VariantType} from "../sha1.js";
import {Sha256VariantType} from "../sha256.js";
import {Sha512VariantType} from "../sha512.js";
import {Sha3VariantType} from "../sha3.js";
import {runHashTests} from "./common.js";

/* The below is less than ideal but rewire can't fiddle with imports so spying is hard */
Object.values({
  ...Sha1VariantType,
  ...Sha256VariantType,
  ...Sha512VariantType,
  ...Sha3VariantType,
}).forEach(variant => {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore - Typescript doesn't understand the above array contains only valid values
  runHashTests(variant, JsSha);
});

describe("Test jsSHA Constructor", () => {
  it("Invalid Variant", () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore - Deliberate bad variant value
    assert.throws(() => new JsSha("SHA-TEST", "HEX"), "Chosen SHA variant is not supported");
  });
});
