import CryptoJS from "crypto-js";
import { md5, sha512 } from "hash-wasm";

const encrypt = (message, key) => {
  const keyHex = CryptoJS.enc.Utf8.parse(key);
  const encrypted = CryptoJS.DES.encrypt(message, keyHex, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });
  return {
    key: keyHex,
    value: encrypted.toString(),
  };
};
const decrypt = (message, key) => {
  const plaintext = CryptoJS.DES.decrypt(message, key, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7,
  });
  return plaintext.toString(CryptoJS.enc.Utf8);
};
const MD5 = md5;
const SHA512 = sha512;

export {
  encrypt,
  decrypt,
  MD5,
  SHA512,
};
