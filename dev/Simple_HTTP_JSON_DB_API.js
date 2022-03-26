const TOKEN = "123456789"
import http from 'http';
http.createServer(async (req, res) => {
    console.log('REQ!')
    const body = new Promise((resolve, reject) => {
        let data = []
        req.on('data', chunk => {
            data.push(chunk)
        })
        req.on('end', () => {
            resolve(Buffer.concat(data).toString())
        })
    })

    const request = {
        body: await body,
        method: req.method,
        url: req.url,
        headers: req.headers
    }
    handledb(request).then(rep => {
        res.writeHead(rep.status || 200, rep.headers)
        res.end(rep.body)
    })
}).listen(19278)
console.log('Server running at http://localhost:19278/')
const handledb = async (req) => {
    const urlObj = new URL(req.url, 'http://localhost')
    const query = key => {
        const query = urlObj.searchParams.get(key)
        if (query) return query
        return null
    }
    if (query('token') !== TOKEN) {
        console.log('Unauthenticated!')
        return gres({ ok: 0 }, { status: 401 })
    }
    let DB = SimpleDB[query('namespace')]
    if (!DB) SimpleDB[query('namespace')] = DB = {}
    console.log(SimpleDB)
    const conf = JSON.parse(query('config'))
    switch (query('action')) {
        case 'read':
            return gres({
                ok: 1,
                data: DB[conf.key]
            })
        case 'write':
            DB[conf['key']] = conf['value']

            return gres({
                ok: 1
            })
        case 'delete':
            delete DB[conf['key']]
            return gres({
                ok: 1
            })
        case 'set':
            DB = conf
            return gres({
                ok: 1
            })
        case 'list':
            return gres({
                ok: 1,
                data: DB
            })
        case 'keys':
            return gres({
                ok: 1,
                data: Object.keys(DB)
            })
        case 'values':
            return gres({
                ok: 1,
                data: Object.values(DB)
            })
        default:
            return gres({
                ok: 0,
                data: 'Unknown action'
            })


    }
}

const SimpleDB = {}


const gres = (body, config) => {
    config = config || {}
    return {
        body: JSON.stringify(body),
        status: config.status ? config.status : 200,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        }
    }

}
