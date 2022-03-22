import handle from '../utils/main.js';
import cons from '../utils/src/cons.js'
import getEnv from '../utils/src/getenv.js';
import MONGODB from '../utils/src/db/MONGODB.js';
import HTTP from '../utils/src/db/HTTP.js';

cons.i('以Vercel形式启动Wexagonal')
export default (req, res) => {

    const t1 = new Date().getTime();

    const PUBLIC_URL = new URL(req.url, 'http://localhost:4000')
    PUBLIC_URL.searchParams.set('token', 'HIDE_TOKEN')
    cons.i(`捕获请求: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()}`)

    const request = {
        body: req.body,
        method: req.method,
        url: req.url,
        headers: req.headers
    }
    handle(request, (() => {

        const config = (() => { try { return JSON.parse(getEnv('DB_CONFIG')); } catch (e) { cons.e('无法解析数据库配置!'); return null } })()
        if (!config) return null
        switch (config.type) {
            case "HTTP":
                return HTTP(config)
            case "MONGODB":
                return MONGODB(config)
            default:
                return null
        }

    })()).then(rep => {
        for (var i in rep.headers) {
            res.setHeader(i, rep.headers[i])
        }
        res.statusCode = rep.status || 200
        cons.s(`响应请求: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()} 耗时: ${new Date().getTime() - t1}ms`)

        res.send(rep.body)
    }).catch(e => {
        cons.e(`响应失败: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()} 耗时: ${new Date().getTime() - t1}ms 错误原因: ${e}`)
        res.statusCode = 500
        res.send()

    })
}