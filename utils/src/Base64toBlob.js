import globalvar from "./globalvar.js"
const Base64toBlob = (base64_data) => {
    const fileatob = (str) => {
        try {
            return Buffer.from(str, 'base64').toString('binary')
        } catch (e) {
            return atob(str)
        }
    }
    const byteString = fileatob(base64_data)
    const arrayBuffer = new ArrayBuffer(byteString.length);
    const intArray = new Uint8Array(arrayBuffer);
    for (let i = 0; i < byteString.length; i++) {
        intArray[i] = byteString.charCodeAt(i);
    }
    return new globalvar.Blob([intArray], { type: 'image/png' });
}

export default Base64toBlob;