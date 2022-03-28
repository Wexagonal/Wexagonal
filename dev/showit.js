
import http from 'http';
http.createServer(async (req, res) => {
    const t1 = new Date().getTime();
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
    console.log(JSON.parse(request.body))
}).listen(process.env.PORT)