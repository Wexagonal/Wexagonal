import CryptoJS from 'crypto-js'
const encrypt = (message, key) => {
    var keyHex = CryptoJS.enc.Utf8.parse(key);
    var encrypted = CryptoJS.DES.encrypt(message, keyHex, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return {
        key: keyHex,
        value: encrypted.toString()
    }
}
const decrypt = (message, key) => {
    var plaintext = CryptoJS.DES.decrypt(message, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    })
    return plaintext.toString(CryptoJS.enc.Utf8)
}
const MD5 = (data) => {
    return CryptoJS.MD5(data).toString()
}
const SHA512 = (data) => {
    return CryptoJS.SHA512(data).toString()
}
const crypa = {
    encrypt,
    decrypt,
    MD5,
    SHA512
}
export default crypa
