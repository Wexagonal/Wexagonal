import { encrypt, decrypt, MD5, SHA512 } from './../src/crypa'
const gsign = (k, u, p) => {
    const uk = `${MD5(u)}:${SHA512(p)}`
    const data = {
        key: k,
        value: uk,
        time: new Date().getTime()
    }
    return encrypt(JSON.stringify(data), k)
}

const gcheck = (k, d, u, p) => {
    let data = decrypt(d, k)
    try {
        data = JSON.parse(data)
        if (data.value === `${MD5(u)}:${SHA512(p)}` && data.key === k && data.time > new Date().getTime() - 1000 * 60 * 60 * 12) {
            return 1
        } else {
            return 0
        }
    } catch (e) {
        return 0
    }
}

export default {
    gsign,
    gcheck
}

