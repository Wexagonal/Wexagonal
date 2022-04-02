import RSASign from "../../src/RSASign.js"
import guuid from '../../src/guuid.js'
import globalvar from "../../src/globalvar.js"
import fetch from 'node-fetch'
import crypa from '../../src/crypa.js'


const gSocial = (config) => {
    //console.log(`fetch endpoint: ${config.endpoint},type ${config.type}`)
    console.log(config.data)
    return fetch(`https://${config.endpoint}/api?type=public&action=social`, {
        method: 'POST',
        body: JSON.stringify({
            type: config.type,
            data: config.encrypt ? crypa.encrypt(JSON.stringify(config.data), config.ckey) : config.data,
            encrypt: config.encrypt,
            endpoint: config.me_endpoint
        })
    })
}




const social_public = async (body, db) => {
    const data = body.data
    
    let res, rep
    const basicConfig = globalvar.DB_DATA.CONFIG.basic
    const socialConfig = basicConfig.social
    let friendSQL =globalvar.DB_DATA.SQL.friend
    if (typeof socialConfig !== 'object') return 'Social is not configured'

    globalvar.me_endpoint = basicConfig.endpoint
    globalvar.me_pub = socialConfig.pub
    globalvar.me_priv = socialConfig.priv
    switch (body.type) {

        case 'FRIEND_REQUEST':
            if (!data.endpoint || !data.pub) return 'Data is not correct'
            globalvar.friend_pub = data.pub
            if (globalvar.me_endpoint !== data.friend_endpoint) return 'Error With The Friend,The Endpoint Is Not The Same'
            if (!RSASign.verify(globalvar.me_endpoint, data.sign, globalvar.friend_pub)) {
                return 'Sign is not correct'
            }
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
            console.log(res)
            if (res.data.verification_key === globalvar.verification_key) {
                friendSQL[data.endpoint] = {
                    ckey: globalvar.ckey,
                    pub: data.pub,
                    time: {
                        add: Date.now(),
                        update: Date.now()
                    },
                    status: 'NEED_CONFIRM'
                }
                res = await fetch(`https://${data.endpoint}/api?type=info`).then(res => res.json())
                friendSQL[data.endpoint].social = res.social
                if (friendSQL[data.endpoint].social.pub === friendSQL[data.endpoint].pub) {
                    delete friendSQL[data.endpoint].social.pub
                } else {
                    return 'Error With The Friend,The RSA Public Key Is Not The Same'
                }
                //await SQL.write('friend', friendSQL)
                    await globalvar.DB.SQL.write('friend', friendSQL)
                return {
                    ckey: globalvar.ckey,
                    pub: socialConfig.pub
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
        case 'FRIEND_REQUEST_ACCEPT':
            globalvar.friend_endpoint = body.endpoint
            globalvar.ckey = friendSQL[globalvar.friend_endpoint].ckey
            globalvar.res = JSON.parse(crypa.decrypt(data, globalvar.ckey))
            if (globalvar.res.friend_endpoint !== globalvar.me_endpoint || globalvar.res.endpoint !== globalvar.friend_endpoint) return 'Error With The Friend,The Endpoint Is Not The Same'
            friendSQL[globalvar.friend_endpoint].status = 'ACCEPT'
            friendSQL[globalvar.friend_endpoint].time.update = Date.now()
            //await SQL.write('friend', friendSQL)
            await globalvar.DB.SQL.write('friend', friendSQL)
            return 'Friend request has been accepted'
        case 'FRIEND_REQUEST_REJECT':
            globalvar.friend_endpoint = body.endpoint
            globalvar.ckey = friendSQL[globalvar.friend_endpoint].ckey
            globalvar.res = JSON.parse(crypa.decrypt(data, globalvar.ckey))
            if (globalvar.res.friend_endpoint !== globalvar.me_endpoint || globalvar.res.endpoint !== globalvar.friend_endpoint) return 'Error With The Friend,The Endpoint Is Not The Same'
            friendSQL[globalvar.friend_endpoint].status = 'REJECT'
            friendSQL[globalvar.friend_endpoint].time.update = Date.now()
            //await SQL.write('friend', friendSQL)
            await globalvar.DB.SQL.write('friend', friendSQL)
            return 'Friend request has been rejected'
        default:
            return 'ERROR!'
    }
}

const social_private = async (body, db) => {

    const data = body.data
    let res;
    const basicConfig =  globalvar.DB_DATA.CONFIG.basic
    const socialConfig = basicConfig.social
    let friendSQL = globalvar.DB_DATA.SQL.friend || {}
    if (typeof socialConfig !== 'object') return 'Social is not configured'

    globalvar.me_endpoint = basicConfig.endpoint
    globalvar.me_pub = socialConfig.pub
    globalvar.me_priv = socialConfig.priv
    switch (body.type) {
        case 'SEND_FRIEND_REQUEST':
            globalvar.friend_endpoint = data.endpoint
            if (!data.endpoint) return 'Data is not correct'
            if (!friendSQL) friendSQL = {}
            //验证是否已经请求过
            if (typeof friendSQL[data.endpoint] !== 'undefined') {
                return 'Friend request has been sent'
            }
            //生成请求
            
            res = await gSocial({
                type: 'FRIEND_REQUEST',
                endpoint: globalvar.friend_endpoint,
                data: {
                    /*
                    ${endpoint} is the endpoint of the friend
                    ${pub} is the public key of the myself
                    ${sign} is the way to prove that the endpoint is the friend,and I had the private key
                    */
                    endpoint: globalvar.me_endpoint,
                    friend_endpoint: globalvar.friend_endpoint,
                    pub: globalvar.me_pub,
                    sign: RSASign.sign(globalvar.friend_endpoint, globalvar.me_priv)
                },
                encrypt: false
            }).then(res => res.json())
            console.log(res)
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
                res = await fetch(`https://${data.endpoint}/api?type=info`).then(res => res.json())
                friendSQL[data.endpoint].social = res.social
                if (friendSQL[data.endpoint].social.pub === friendSQL[data.endpoint].pub) {
                    delete friendSQL[data.endpoint].social.pub
                } else {
                    return 'Error With The Friend,The RSA Public Key Is Not The Same'
                }

                //await SQL.write('friend', friendSQL)
                await globalvar.DB.SQL.write('friend', friendSQL)
                return 'Friend request has been sent'
            }

            return 'ERROR!'

        case 'LIST_FRIENDS':
            if (!friendSQL) friendSQL = {}
            //await SQL.write('friend', friendSQL)
            await globalvar.DB.SQL.write('friend', friendSQL)
            return friendSQL
        case 'ACCEPT_FRIEND_REQUEST':
            globalvar.friend_endpoint = data.endpoint

            if (!globalvar.friend_endpoint) return 'Data is not correct'
            if (!friendSQL) friendSQL = {}
            if (typeof friendSQL[data.endpoint] === 'undefined') {
                return 'Friend request is not found'
            }
            if (friendSQL[data.endpoint].status !== 'NEED_CONFIRM') {
                return 'Friend request is not in pending status'
            }
            
            globalvar.friend_ckey = friendSQL[data.endpoint].ckey
            res = await gSocial({
                type: 'FRIEND_REQUEST_ACCEPT',
                endpoint: globalvar.friend_endpoint,
                me_endpoint: globalvar.me_endpoint,
                data: {
                    endpoint: globalvar.me_endpoint,
                    friend_endpoint: globalvar.friend_endpoint
                },
                encrypt: true,
                ckey: globalvar.friend_ckey

            }).then(res => res.json())
            if (res.ok) {
                friendSQL[data.endpoint].status = 'ACCEPT'
                friendSQL[data.endpoint].time.update = Date.now()
                //await SQL.write('friend', friendSQL)
                await globalvar.DB.SQL.write('friend', friendSQL)
                return 'Friend request has been accepted'
            }
            return 'ERROR!'

        case 'REJECT_FRIEND_REQUEST':
            globalvar.friend_endpoint = data.endpoint
            if (!globalvar.friend_endpoint) return 'Data is not correct'
            if (!friendSQL) friendSQL = {}
            if (typeof friendSQL[data.endpoint] === 'undefined') {
                return 'Friend request is not found'
            }
            res = await gSocial({
                type: 'FRIEND_REQUEST_REJECT',
                endpoint: globalvar.friend_endpoint,
                me_endpoint: globalvar.me_endpoint,
                data: {
                    endpoint: globalvar.me_endpoint,
                    friend_endpoint: globalvar.friend_endpoint
                },
                encrypt: true,
                ckey: globalvar.friend_ckey
            }).then(res => res.json())
            if (res.ok) {
                friendSQL[data.endpoint].status = 'REJECT'
                friendSQL[data.endpoint].time.update = Date.now()
                //await SQL.write('friend', friendSQL)
                await globalvar.DB.SQL.write('friend', friendSQL)
                return 'Friend request has been rejected'
            }
            return 'ERROR!'
        case 'DELETE_FRIEND':
            globalvar.friend_endpoint = data.endpoint
            delete friendSQL[globalvar.friend_endpoint]
            globalvar.DB.SQL.write('friend', friendSQL)
            return 'Friend has been deleted'




    }
}
const social = {
    private: social_private,
    public: social_public
}

export default social