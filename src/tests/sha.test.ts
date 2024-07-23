import JsSha from "../sha.js";
import {Sha1VariantType} from "../sha1.js";
import {Sha256VariantType} from "../sha256.js";
import {Sha512VariantType} from "../sha512.js";
import {Sha3VariantType} from "../sha3.js";
import {JsShaCtor, runHashTests} from "./common.js";

/* The below is less than ideal but rewire can't fiddle with imports so spying is hard */
Object.values({
  ...Sha1VariantType,
  ...Sha256VariantType,
  ...Sha512VariantType,
  ...Sha3VariantType,
}).forEach(variant => {
  runHashTests(variant, JsSha as unknown as JsShaCtor);
});
