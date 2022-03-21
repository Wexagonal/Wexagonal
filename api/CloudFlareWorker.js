import handle from "../utils/main.js"

//Import DB

import KV from "../utils/src/db/KV.js"
import HTTP from "../utils/src/db/HTTP.js"

import getEnv from "../utils/src/getenv.js"
addEventListener('fetch', event => {
    event.respondWith(generate_response(event.request))
})

const generate_response = async (req) => {
    const request = {
        body: await req.text(),
        method: req.method,
        url: req.url,
        headers: req.headers
    }
    const res = await handle(request, (() => {

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

    })())
    return new Response(res.body, {
        status: res.statusCode || 200,
        headers: res.headers
    })
}