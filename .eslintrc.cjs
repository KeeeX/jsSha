const eslintConfig = require("@keeex/eslint-config");
module.exports = eslintConfig({
  typescript: "./tsconfig.json",
  mocha: true,
});
