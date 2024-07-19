import { describe, it } from "mocha";
import { assert } from "chai";
import jsSHA from "../sha.js";
import { runHashTests } from "./common.js";
import { Variant } from "./data/hash_data.js";

/* The below is less than ideal but rewire can't fiddle with imports so spying is hard */
Object.values(Variant).forEach((variant) => {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore - Typescript doesn't understand the above array contains only valid values
  runHashTests(variant, jsSHA);
});

describe("Test jsSHA Constructor", () => {
  it("Invalid Variant", () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore - Deliberate bad variant value
    assert.throws(() => new jsSHA("SHA-TEST", "HEX"), "Chosen SHA variant is not supported");
  });
});
