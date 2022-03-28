import RSASign from "../../src/RSASign.js"
import guuid from '../../src/guuid.js'
import globalvar from "../../src/globalvar.js"
import fetch from 'node-fetch'
import crypa from '../../src/crypa.js'
const Pri = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0eTBVQVioox+O
Ruqx6zqRGh1jOqUKWXNG6N0oqu+Cvflw6H2MEPckl+cipcn52+8ExKAarixMevxW
OHclcXZXDHHlPB5Q/j3nEZ+bzywAlabDn63+q+K3QDcIBNH/e75k8nOSdaGz0zXp
cDQhuAa3saAFV6gsVtHki0lKEEFnsS3jvZfzc3IFnJFUAG+Nf1BzFaqwV/1NFGuB
Y9SGGYmtXGSiVV7Q2MTYX2MY5aytcQgldScAIzkhgsgFbuWd+K+0YLPq/XbOe7Pt
s4/X2V29ycZUjiV1V9UpXjcv/QdEkZQbxs/bVd90k/Oewa2cQpYd7F/vpRiDMxpy
rnS9Q8L9AgMBAAECggEANqngcGpXGtkx5SvoyZQ4zJuO3C/2rnBSoN9GoZtI6Z52
L/NTl7nJye0yxsVVrJcnyhducTZhV5cG2GzI9e/sishLtUXk3t5rTJKDeDOjnde2
R9mVX6abiKrsIEMpgktua3AefnWf0XJ/iWIBgFcXvcsQ751R5IA1mhZwT/0lemzm
/e4sZ/McrbupKvhTZmh+NYIBkezoIywOBfqzzdHosyBd9BLH7J3pSReyEnQt3UAH
pN8HI0PP+hP0MDYaG/bbg476uFXnMNL7w7so6v9NklBoJlA+QOLTRbpELmdJ/qYg
s13iB0xyWU4y4VNDWLBdw+Y2XT+CetlVeCDaPYqIVwKBgQDrQOYiiDtOheaBQCao
GhZ+7utZcWfbH9uvYQNs5GocS8vgqFkHSCt9O8qJTtgAz23DwrGQyHr9/dkzsB7P
OjRkXMSr7diRK0jOHrt012p9YlqkD8qKu6VX8gn+o06Tg7co35o1AVKTNKNIBdO8
Fs8oHPdOoWpou+WsWV0ZsyCzPwKBgQDEY5Hb4Q9W2Q88emjO7X6eR2NjrqCqQimz
m6MxDcEdS0QJ8fEYpwE/3GFT1sDMWqu1WL3FOJRzhhaxQ6Jz3/dLHHXScF2M8i46
YVtwJe0yHMVSK2D/ZkNQTBrGagkgyP7l9raQw6hERss/vpXJsqTCT38lXc9J9piR
HPT2B6hGwwKBgQDBYlMLlfMypE2MeCCO1QsjAuGCX//gl/qt21DGhalYY1JP9fNh
Ugk15B2k66QSXnE7l+MBQlwgSDjxDVj2PkFtMvkU3+rDwtIRZh/wd1f5hA1Aih6U
FpZfif5/TN090+uPdOe9pL2tdnq2rNuV5SYbMlx1Tak8OSEeoUMv6hj6XwKBgAnL
wanLFx3I4/arUHEJ7aftfaqqOj9j33qjB8fZnMleSL2KQPFu2yQZVQ1+h81ptGju
TUD6KoV8qcMb0Y2gHVC00be2fSQbrGyjEJGOgr9eKgWIPmVe73qg4TEGdwAYpoZI
ASFFcS4+rcK3Ofd+nrNGjdwKSt2wnDmYzSs8hItLAoGBAM87ZnJw2HCs/99zgiVF
l+6LYFmhfvCwCmX4gjVcsxKOt7sbEpUaVFBNNPiTv1CEU3VGEVLMu3faqBiFOWt5
QKkKVujZlaevctYhkpCAyB4WvgHyIrQopwExhgzP4Ity8YMoqSwQkUqzPxd8coWb
NdfLuRguMP7scJH3KWiIF67T
-----END PRIVATE KEY-----`
const Pub = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtHkwVUFYqKMfjkbqses6
kRodYzqlCllzRujdKKrvgr35cOh9jBD3JJfnIqXJ+dvvBMSgGq4sTHr8Vjh3JXF2
Vwxx5TweUP495xGfm88sAJWmw5+t/qvit0A3CATR/3u+ZPJzknWhs9M16XA0IbgG
t7GgBVeoLFbR5ItJShBBZ7Et472X83NyBZyRVABvjX9QcxWqsFf9TRRrgWPUhhmJ
rVxkolVe0NjE2F9jGOWsrXEIJXUnACM5IYLIBW7lnfivtGCz6v12znuz7bOP19ld
vcnGVI4ldVfVKV43L/0HRJGUG8bP21XfdJPznsGtnEKWHexf76UYgzMacq50vUPC
/QIDAQAB
-----END PUBLIC KEY-----`


const gSocial = (config) => {
    console.log(`fetch endpoint: ${config.endpoint},type ${config.type}`)
    return fetch(`http://${config.endpoint}/api?type=public&action=social`, {
        method: 'POST',
        body: JSON.stringify({
            type: config.type,
            data: config.encrypt ? crypa.encrypt(JSON.stringify(config.data), config.ckey) : config.data
        })
    })
}

const social = async (body, db) => {
    const data = body.data
    //console.log(body)
    if (!data || typeof data !== 'object') return 'Data type is not correct'
    let res;
    /*const CONFIG = await (await db)('CONFIG')
    const socialConfig = await CONFIG.read('social')*/
    const socialConfig = {
        privkey: Pri,
        pubkey: Pub,
        endpoint: 'localhost:3000'
    }
    if (typeof socialConfig !== 'object') return 'Social is not configured'
    switch (body.type) {
        case 'FRIEND_REQUEST':
            if (!data.endpoint || !data.pubkey) return 'Data is not correct'
            globalvar.verification_key = guuid()
            globalvar.ckey = guuid()
            res = await gSocial({
                type: 'VERRIFY_ENDPOINT',
                data: {
                    verification_key: crypa.encrypt(globalvar.verification_key, globalvar.ckey),
                    enpoint: socialConfig.endpoint,
                    pubkey: socialConfig.pubkey,
                    ckey: RSASign.en(globalvar.ckey, data.pubkey)
                },
                endpoint: data.endpoint,
                privkey: socialConfig.privkey,
                pubkey: socialConfig.pubkey,
                encrypt: false

            }).then(res => res.json())
            if(res.data.verification_key === globalvar.verification_key){
                console.log({
                    type:"VERIFY_SUCCESS",
                    ckey: globalvar.ckey,
                    mePubkey: socialConfig.pubkey,
                    friendPubkey: data.pubkey
                })
            }
            return res
        case 'VERRIFY_ENDPOINT':
            if (!data.verification_key || !data.pubkey || !data.ckey) return 'Data is not correct'
            globalvar.ckey = RSASign.de(data.ckey, socialConfig.privkey)
            return {
                pubkey: crypa.encrypt(socialConfig.pubkey, globalvar.ckey),
                verification_key: crypa.decrypt(data.verification_key, globalvar.ckey)
            }
        default:
            return 'ERROR!'
    }
}
export default social