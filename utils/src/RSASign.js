import rs from "jsrsasign";
import b64 from './b64.js'
/*
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
-----END PUBLIC KEY-----`*/

const RSASign = {
    en:(dara,Pub)=>{
        //using jsrsasign
        var key = rs.KEYUTIL.getKey(Pub);
        var plainText = dara;
        var base64 = b64.en(plainText);
        return rs.KJUR.crypto.Cipher.encrypt(base64, key);
    },
    de:(dara,Pri)=>{
        //using jsrsasign
        var key = rs.KEYUTIL.getKey(Pri);
        var base64 = dara;
        var plainText = rs.KJUR.crypto.Cipher.decrypt(base64, key);
        return b64.de(plainText);
    },
    sign:(dara,Pri)=>{
        //using jsrsasign
        var key = rs.KEYUTIL.getKey(Pri);
        var plainText = dara;
        var base64 = b64.en(plainText);
        let sig = new rs.KJUR.crypto.Signature({alg:"SHA1withRSA"});
        sig.init(key)
        sig.updateString(base64);
        return sig.sign();
    },
    verify:(dara,sign,Pub)=>{
        var key = rs.KEYUTIL.getKey(Pub);
        var plainText = dara;
        var base64 = b64.en(plainText);
        let sig = new rs.KJUR.crypto.Signature({alg:"SHA1withRSA"});
        sig.init(key)
        sig.updateString(base64);
        return sig.verify(sign);
        
    }


}
export default RSASign