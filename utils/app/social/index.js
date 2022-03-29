import RSASign from "../../src/RSASign.js"
import guuid from '../../src/guuid.js'
import globalvar from "../../src/globalvar.js"
import fetch from 'node-fetch'
import crypa from '../../src/crypa.js'


const gSocial = (config) => {
    //console.log(`fetch endpoint: ${config.endpoint},type ${config.type}`)
    //console.log(config.data)
    return fetch(`https://${config.endpoint}/api?type=public&action=social`, {
        method: 'POST',
        body: JSON.stringify({
            type: config.type,
            data: config.encrypt ? crypa.encrypt(JSON.stringify(config.data), config.ckey) : config.data
        })
    })
}

const social_public = async (body, db) => {
    const data = body.data
    //console.log(body)
    if (!data || typeof data !== 'object') return 'Data type is not correct'
    let res, rep
    const CONFIG = await (await db)('CONFIG')
    const SQL = await (await db)('SQL')
    const basicConfig = await CONFIG.read('basic')
    const socialConfig = basicConfig.social
    let friendSQL = await SQL.read('friend')
    if (typeof socialConfig !== 'object') return 'Social is not configured'
    switch (body.type) {

        case 'FRIEND_REQUEST':
            if (!data.endpoint || !data.pub) return 'Data is not correct'
            globalvar.verification_key = guuid()
            globalvar.ckey = guuid()
            if (!friendSQL) friendSQL = {}
            if (typeof friendSQL[data.endpoint] === 'undefined') {
                friendSQL[data.endpoint] = {}
            } else if (friendSQL[data.endpoint].status === 'BLOCKED') {
                return 'Friend request is blocked'
            } else {
                return 'Friend request has been sent'
            }
            res = await gSocial({
                type: 'VERRIFY_ENDPOINT',
                data: {
                    verification_key: crypa.encrypt(globalvar.verification_key, globalvar.ckey),
                    endpoint: basicConfig.endpoint,
                    pub: socialConfig.pub,
                    ckey: RSASign.en(globalvar.ckey, data.pub)
                },
                endpoint: data.endpoint,
                priv: socialConfig.priv,
                pub: socialConfig.pub,
                encrypt: false

            }).then(res => res.json())
            if (res.data.verification_key === globalvar.verification_key) {
                friendSQL[data.endpoint] = {
                    ckey: globalvar.ckey,
                    pub: data.pub,
                    time: {
                        add: Date.now(),
                        update: Date.now()
                    },
                    status: 'PENDING'
                }
                await SQL.write('friend', friendSQL)
                return {
                    ckey: globalvar.ckey,
                    pub: data.pub
                }
            } else {
                return {
                    ckey: null
                }
            }
        case 'VERRIFY_ENDPOINT':
            if (!data.verification_key || !data.pub || !data.ckey) return 'Data is not correct'
            globalvar.ckey = RSASign.de(data.ckey, socialConfig.priv)
            return {
                pub: crypa.encrypt(socialConfig.pub, globalvar.ckey),
                verification_key: crypa.decrypt(data.verification_key, globalvar.ckey)
            }
        case 'FRIEND_REQUEST_RESPONSE':
            rep = crypa.decrypt(data.data, globalvar.ckey)
            switch (req.response) {
                case 'ACCEPT':
                    if (!friendSQL[rep.endpoint]) return 'Friend request has been rejected'
                    friendSQL[rep.endpoint].status = 'ACCEPT'
                case 'REJECT':
                    if (!friendSQL[rep.endpoint]) return 'Friend request has been rejected'
                    friendSQL[rep.endpoint].status = 'REJECT'
                case 'BLOCK':
                    if (!friendSQL[rep.endpoint]) return 'Friend request has been rejected'
                    friendSQL[rep.endpoint].status = 'BLOCK'
            }
            friendSQL[rep.endpoint].time.update = Date.now()
            await SQL.write('friend', friendSQL)
            return {
                ok: true
            }
        default:
            return 'ERROR!'
    }
}

const social_private = async (body, db) => {

    const data = body.data
    if (!data || typeof data !== 'object') return 'Data type is not correct'
    let res;
    const CONFIG = await (await db)('CONFIG')
    const SQL = await (await db)('SQL')
    const basicConfig = await CONFIG.read('basic')
    const socialConfig = basicConfig.social
    let friendSQL = await SQL.read('friend')
    if (typeof socialConfig !== 'object') return 'Social is not configured'
    switch (body.type) {
        case 'SEND_FRIEND_REQUEST':
            if (!data.endpoint) return 'Data is not correct'
            if (!friendSQL) friendSQL = {}
            if (typeof friendSQL[data.endpoint] !== 'undefined') {
                  return 'Friend request has been sent'
            }

            res = await gSocial({
                type: 'FRIEND_REQUEST',
                endpoint: data.endpoint,
                data: {
                    endpoint: basicConfig.endpoint,
                    pub: socialConfig.pub
                },
                encrypt: false
            }).then(res => res.json())
            if (!!res.data.ckey) {
                friendSQL[data.endpoint] = {
                    ckey: res.data.ckey,
                    pub: res.data.pub,
                    time: {
                        add: Date.now(),
                        update: Date.now()
                    },
                    status: 'PENDING'
                }
                await SQL.write('friend', friendSQL)
                return 'Friend request has been sent'
            }

            return 'ERROR!'
        case 'LIST_FRIEND':
            if (!friendSQL) friendSQL = {}
            await SQL.write('friend', friendSQL)
            return friendSQL
        case 'RESPONSE_FRIEND_REQUEST':
            if (!data.endpoint) return 'Data is not correct'
            if (!friendSQL) friendSQL = {}
            if (typeof friendSQL[data.endpoint] === 'undefined') {
                return 'Friend request is not found'
            }
            if (friendSQL[data.endpoint].status === data.response) {
                return `Friend request is already ${data.response}`
            }
            res = await gSocial({
                type: 'FRIEND_REQUEST_RESPONSE',
                endpoint: data.endpoint,
                data: {
                    response: data.response,
                    ckey: friendSQL[data.endpoint].ckey
                },
                encrypt: true,
                ckey: friendSQL[data.endpoint].ckey
            }).then(res => res.json())
            if (res.ok) {
                friendSQL[data.endpoint].status = data.response
                friendSQL[data.endpoint].time.update = Date.now()
                await SQL.write('friend', friendSQL)
                return 'Friend request has been responded'
            }else{
                return 'ERROR!'
            }
    }
}
const social = {
    private: social_private,
    public: social_public
}

export default social