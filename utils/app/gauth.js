import crypa from './../src/crypa.js'
const gauth = {
    gsign: (k, u, p) => {
        const t = new Date().getTime()
        const uk = `${crypa.MD5(u)}:${crypa.SHA512(p)}:${t}`
        const data = {
            key: k,
            value: uk,
            time: t
        }
        return crypa.encrypt(JSON.stringify(data), k)
    },
    gcheck: (k, u, p, d) => {
        try {
            const data = JSON.parse(crypa.decrypt(d, k))
            const uk = `${crypa.MD5(u)}:${crypa.SHA512(p)}:${data.time}`
            return data.value === uk && data.time > new Date().getTime() - 12 * 60 * 60 * 1000 && data.key === k
        } catch (e) {
            return false
        }
    }
}

export default gauth