import handle from "../utils/main.js"

//Import DB

import KV from "../utils/src/db/KV.js"
import HTTP from "../utils/src/db/HTTP.js"

import getEnv from "../utils/src/getenv.js"

import cons from "../utils/src/cons.js"
addEventListener('fetch', event => {
    event.respondWith(generate_response(event.request))
})

cons.i('以WebWorker形式启动Wexagonal')
const generate_response = async (req) => {
    const t1 = new Date().getTime()
    const PUBLIC_URL = new URL(req.url, 'http://localhost:4000')
    PUBLIC_URL.searchParams.set('token', 'HIDE_TOKEN')
    const request = {
        body: await req.text(),
        method: req.method,
        url: req.url,
        headers: req.headers
    }

    cons.i(`捕获请求: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()}`)
    return handle(request, (() => {

        const config = (() => { try { return JSON.parse(getEnv('DB_CONFIG')); } catch (e) { return null } })()
        if (!config) return null
        switch (config.type) {
            case "KV":
                return KV(config)
            case "HTTP":
                return HTTP(config)
            default:
                return null
        }

    })()).then(res => {
        cons.s(`响应请求: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()} 耗时: ${new Date().getTime() - t1}ms`)

        return new Response(res.body, {
            status: res.statusCode || 200,
            headers: res.headers
        })
    })

        .catch(e => {
            cons.e(`响应请求: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()} 耗时: ${new Date().getTime() - t1}ms 错误: ${e}`)

            return new Response(null, {
                status: 500,
                headers: {
                    'Access-Control-Allow-Origin': '*'
                }
            })
        })

}