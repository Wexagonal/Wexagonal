module.exports = {
  env: {
    browser: true,
    es2021: true,
  },
  extends: [
    "@so1ve",
  ],
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
  },
  rules: {
    "no-console": "off",
  },
};
