//Generate Response 快速生成响应
import gres from './src/gres.js'
import fetch, {
    Blob,
    blobFrom,
    blobFromSync,
    File,
    fileFrom,
    fileFromSync,
    FormData,
    Headers,
    Request,
    Response,
} from 'node-fetch'

if (typeof self === 'undefined') {
    const self = this || {}
}
if (!self.FormData) {
    self.FormData = FormData
}
import crypa from './src/crypa.js'
import hexo from './app/hexo.js'
import github from './app/github.js'
//Wexagonal安装测试app
import tester from './app/test.js'
import Base64toBlob from './src/Base64toBlob.js'

const handle = async (req, db) => {
    const global = {}
    const urlObj = new URL(req.url, 'http://localhost')
    const q = key => {
        return urlObj.searchParams.get(key) || null
    }
    if (!db) {
        return gres({
            ok: 1,
            db: 0,
            install: 0
        })
    }
    const CONFIG = await (await db)('CONFIG')
    const SQL = await (await db)('SQL')


    if (!await CONFIG.read('install')) {
        if (q('type') == 'test') return tester(req, db)
        if (q('type') == 'upload') {
            global.data = JSON.parse(q('data'))
            for (var i in global.data) {
                await CONFIG.write(i, global.data[i])
            }
            await CONFIG.write('install', true)
            return gres({
                ok: 1,
                data: await CONFIG.list()
            })
        }
        return gres({
            ok: 1,
            db: 1,
            install: 0
        })
    }

    global.gtoken = crypa.MD5((await CONFIG.read('basic'))['username']) + crypa.SHA512((await CONFIG.read('basic'))['password'])
    global.admin = crypa.MD5(q('username')) + crypa.SHA512(q('password')) === global.gtoken || q('token') === global.gtoken ? 1 : 0
    let hexoConfig;
    let imgConfig;
    let imgList

    switch (q('type')) {
        case 'file':
            if (!global.admin) return gres({ ok: 0, admin: 0 })
            hexoConfig = await CONFIG.read('hexo')
            switch (q('action')) {
                case 'list':
                    return gres({
                        ok: 1,
                        data: (await github.file.list({
                            token: hexoConfig.token,
                            repo: hexoConfig['repo'],
                            path: q('path')
                        }))['data']
                    })
            }
        case 'img':
            if (!global.admin) return gres({ ok: 0, admin: 0 })
            imgConfig = await CONFIG.read('img')
            if (!imgConfig || imgConfig.length == 0) return gres({ ok: 0, img: 0 })
            imgConfig = imgConfig[0]
            imgList = await SQL.read('img') || {
                count: 0,
                data: {}

            }


            switch (q('action')) {
                case 'upload':
                    const formData = new self.FormData()
                    formData.append(imgConfig.fieldName, Base64toBlob(req.body), `${new Date().getTime()}.jpg`)
                    return gres({
                        ok: 1,
                        data: await (async () => {
                            const download_res = await (await fetch(imgConfig.url, {
                                method: 'POST',
                                body: formData,
                                headers: {
                                    ...imgConfig.headers
                                }
                            })).json()
                            for (var q in imgConfig.path) {

                                const path_list = imgConfig.path[q].split('.')

                                const returnner = (array, path_list) => {
                                    if (path_list.length == 0) return array
                                    const path = path_list.shift()
                                    if (!array[path]) return ''
                                    return returnner(array[path], path_list)
                                }
                                const returnres = returnner(download_res, path_list)
                                if (returnres == '') continue
                                let resurl
                                if (!!imgConfig.beautify) {
                                    resurl = imgConfig.beautify.replace(/\$\{\}/g, returnres)
                                } else {
                                    resurl = returnres
                                }

                                imgList.data[imgList.count] = {
                                    id: imgList.count,
                                    url: resurl,
                                    host: 0,
                                    time: new Date().getTime()

                                }
                                imgList.count += 1
                                await SQL.write('img', imgList)
                                return resurl
                            }
                            return 'ERROR,the path is not correct'
                        })()
                    })
                case 'config':
                    return gres({
                        ok: 1,
                        data: imgConfig
                    })
                case 'list':

                    return gres({
                        ok: 1,
                        data: imgList
                    })
                case 'delete':
                    //url
                    for (var i in imgList.data) {
                        if (imgList.data[i].url == q('url')) {
                            delete imgList.data[i]
                        }
                    }
                    await SQL.write('img', imgList)
                    return gres({
                        ok: 1
                    })
            }


        case 'hexo':
            if (!global.admin) return gres({ ok: 0, admin: 0 })
            hexoConfig = await CONFIG.read('hexo')
            switch (q('action')) {
                case "config":
                    return gres({
                        ok: 1,
                        data: hexoConfig
                    })
                case 'dispatch':
                    return gres({
                        ok: 1,
                        data: await github.workflow.dispatch({
                            token: hexoConfig.token,
                            repo: hexoConfig['repo'],
                            name: hexoConfig["workflow"],
                            branch: hexoConfig['branch']
                        })
                    })
                case 'cancel':
                    return gres({
                        ok: 1,
                        data: await github.run.cancel({
                            token: hexoConfig.token,
                            repo: hexoConfig['repo'],
                            branch: hexoConfig['branch'],
                            name: hexoConfig['workflow']
                        })
                    })
                case 'getci':
                    return gres({
                        ok: 1,
                        data: (await hexo.app.check_run({
                            token: hexoConfig.token,
                            repo: hexoConfig['repo'],
                            branch: hexoConfig['branch'],
                            name: hexoConfig['workflow']
                        }))
                    })

                case 'count':
                    return gres({
                        ok: 1,
                        data: await hexo.app.count({
                            token: hexoConfig.token,
                            repo: hexoConfig.repo,
                            branch: hexoConfig.branch,
                            path: q('gettype') === "post" ? "/source/_posts/" : "/source/_drafts/"
                        })
                    })
                case 'list':
                    return gres({
                        ok: 1,
                        data: await hexo.app.list({
                            token: hexoConfig.token,
                            repo: hexoConfig.repo,
                            branch: hexoConfig.branch,
                            path: q('gettype') === "post" ? "/source/_posts/" : "/source/_drafts/"
                        })
                    })
                case 'download':
                    return gres({
                        ok: 1,
                        data: await hexo.app.download({
                            token: hexoConfig.token,
                            repo: hexoConfig.repo,
                            branch: hexoConfig.branch,
                            path: q('path')
                        })
                    })
                case 'upload':
                    return gres({
                        ok: 1,
                        data: await hexo.app.upload({
                            token: hexoConfig.token,
                            repo: hexoConfig.repo,
                            branch: hexoConfig.branch,
                            path: q('path'),

                            content: req.body
                        })
                    })
                case 'delete':
                    return gres({
                        ok: 1,
                        data: await hexo.app.delete({
                            token: hexoConfig.token,
                            repo: hexoConfig.repo,
                            branch: hexoConfig.branch,
                            path: q('path')
                        })
                    })
                case 'move':
                    return gres({
                        ok: 1,
                        data: await github.file.move({
                            token: hexoConfig.token,
                            repo: hexoConfig.repo,
                            branch: hexoConfig.branch,
                            path: q('path'),
                            newpath: q('newpath')
                        })
                    })


            }
        case 'public':
            return gres({
                ok: 0
            })

        case 'sign':
            if (!global.admin) return gres({ ok: 0 })
            return gres({
                ok: 1,
                data: crypa.MD5(q('username')) + crypa.SHA512(q('password'))
            })
        case 'config':
            if (!global.admin) return gres({ ok: 0 })

            const ALL_CONFIG = await CONFIG.list()
            switch (q('action')) {
                case 'list':
                    ALL_CONFIG['hexo']['token'] = '!!GithubToken被保护!!'
                    ALL_CONFIG['basic']['password'] = '!!密码被保护!!'
                    return gres({
                        ok: 1,
                        data: ALL_CONFIG
                    })
                case 'upload':
                    const ALL_UPLOAD_CONFIG = JSON.parse(q('config'))
                    ALL_UPLOAD_CONFIG['hexo']['token'] = ALL_CONFIG['hexo']['token']
                    ALL_UPLOAD_CONFIG['basic']['password'] = ALL_CONFIG['basic']['password']
                    for (var i in ALL_UPLOAD_CONFIG) {
                        await CONFIG.write(i, ALL_UPLOAD_CONFIG[i])
                    }
                    return gres({ ok: 1 })

                default:
                    return gres({
                        ok: 0
                    })
            }
        default:
            return gres({
                ok: 1,
                db: 1,
                install: await CONFIG.read('install') ? 1 : 0,
                admin: global.admin,
                version: '0.0.1'
            })
    }
}
export default handle