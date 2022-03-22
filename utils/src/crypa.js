import CryptoJS from 'crypto-js'
const encrypt = (message, key) => {
    return CryptoJS.AES.encrypt(message, key).toString()
}
const decrypt = (message, key) => {
    return CryptoJS.AES.decrypt(message, key).toString(CryptoJS.enc.Utf8)
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
