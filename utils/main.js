import globalvar from './src/globalvar.js'

//Generate Response 快速生成响应
import gres from './src/gres.js'

import gauth from './app/gauth.js'

import guuid from './src/guuid.js'
import crypa from './src/crypa.js'
import hexo from './app/hexo.js'
import github from './app/github.js'
//Wexagonal安装测试app
import tester from './app/test.js'
import Base64toBlob from './src/Base64toBlob.js'

const handle = async (req, db) => {
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
    globalvar.install = await CONFIG.read('install')

    if (!globalvar.install) {
        if (q('type') == 'test') return tester(req, db)
        if (q('type') == 'upload') {
            globalvar.data = JSON.parse(q('data'))
            for (var i in globalvar.data) {
                await CONFIG.write(i, globalvar.data[i])
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
    globalvar.basicConfig = await CONFIG.read('basic')
    if (typeof globalvar.basicConfig === 'undefined') {
        //意外退出
        return gres({ ok: 0, data: "绝对的异常错误,无法找到基础Hexo设置" })

    } else if (typeof globalvar.basicConfig.key === 'undefined') {
        globalvar.basicConfig.key = guuid()
        await CONFIG.write('basic', globalvar.basicConfig)
    }

    globalvar.sign = gauth.gsign(
        globalvar.basicConfig.key,
        q('user'),
        q('pass')
    )
    globalvar.admin = gauth.gcheck(
        globalvar.basicConfig.key,
        globalvar.basicConfig.user,
        globalvar.basicConfig.pass,
        q('token')
    )

    switch (q('type')) {
        case 'file':
            if (!globalvar.admin) return gres({ ok: 0, admin: 0 })
            globalvar.hexoConfig = await CONFIG.read('hexo')
            switch (q('action')) {
                case 'list':
                    return gres({
                        ok: 1,
                        data: (await github.file.list({
                            token: globalvar.hexoConfig.token,
                            repo: globalvar.hexoConfig['repo'],
                            path: q('path')
                        }))['data']
                    })
            }
        case 'img':
            if (!globalvar.admin) return gres({ ok: 0, admin: 0 })
            globalvar.imgConfig = await CONFIG.read('img')
            if (!globalvar.imgConfig || globalvar.imgConfig.length == 0) return gres({ ok: 0, img: 0 })
            globalvar.imgConfig = globalvar.imgConfig[0]
            globalvar.imgList = await SQL.read('img') || {
                count: 0,
                data: {}

            }


            switch (q('action')) {
                case 'upload':
                    const formData = new globalvar.FormData()
                    formData.append(globalvar.imgConfig.fieldName, Base64toBlob(req.body), `${new Date().getTime()}.jpg`)
                    return gres({
                        ok: 1,
                        data: await (async () => {
                            const download_res = await (await fetch(globalvar.imgConfig.url, {
                                method: 'POST',
                                body: formData,
                                headers: {
                                    ...globalvar.imgConfig.headers
                                }
                            })).json()
                            for (var q in globalvar.imgConfig.path) {

                                const path_list = globalvar.imgConfig.path[q].split('.')

                                const returnner = (array, path_list) => {
                                    if (path_list.length == 0) return array
                                    const path = path_list.shift()
                                    if (!array[path]) return ''
                                    return returnner(array[path], path_list)
                                }
                                const returnres = returnner(download_res, path_list)
                                if (returnres == '') continue
                                let resurl
                                if (!!globalvar.imgConfig.beautify) {
                                    resurl = globalvar.imgConfig.beautify.replace(/\$\{\}/g, returnres)
                                } else {
                                    resurl = returnres
                                }

                                globalvar.imgList.data[globalvar.imgList.count] = {
                                    id: globalvar.imgList.count,
                                    url: resurl,
                                    host: 0,
                                    time: new Date().getTime()

                                }
                                globalvar.imgList.count += 1
                                await SQL.write('img', globalvar.imgList)
                                return resurl
                            }
                            return 'ERROR,the path is not correct'
                        })()
                    })
                case 'config':
                    return gres({
                        ok: 1,
                        data: globalvar.imgConfig
                    })
                case 'list':

                    return gres({
                        ok: 1,
                        data: globalvar.imgList
                    })
                case 'delete':
                    //url
                    for (var i in globalvar.imgList.data) {
                        if (globalvar.imgList.data[i].url == q('url')) {
                            delete globalvar.imgList.data[i]
                        }
                    }
                    await SQL.write('img', globalvar.imgList)
                    return gres({
                        ok: 1
                    })
            }


        case 'hexo':
            if (!globalvar.admin) return gres({ ok: 0, admin: 0 })
            globalvar.hexoConfig = await CONFIG.read('hexo')
            switch (q('action')) {
                case "config":
                    return gres({
                        ok: 1,
                        data: globalvar.hexoConfig
                    })
                case 'dispatch':
                    return gres({
                        ok: 1,
                        data: await github.workflow.dispatch({
                            token: globalvar.hexoConfig.token,
                            repo: globalvar.hexoConfig['repo'],
                            name: globalvar.hexoConfig["workflow"],
                            branch: globalvar.hexoConfig['branch']
                        })
                    })
                case 'cancel':
                    return gres({
                        ok: 1,
                        data: await github.run.cancel({
                            token: globalvar.hexoConfig.token,
                            repo: globalvar.hexoConfig['repo'],
                            branch: globalvar.hexoConfig['branch'],
                            name: globalvar.hexoConfig['workflow']
                        })
                    })
                case 'getci':
                    return gres({
                        ok: 1,
                        data: (await hexo.app.check_run({
                            token: globalvar.hexoConfig.token,
                            repo: globalvar.hexoConfig['repo'],
                            branch: globalvar.hexoConfig['branch'],
                            name: globalvar.hexoConfig['workflow']
                        }))
                    })

                case 'count':
                    return gres({
                        ok: 1,
                        data: await hexo.app.count({
                            token: globalvar.hexoConfig.token,
                            repo: globalvar.hexoConfig.repo,
                            branch: globalvar.hexoConfig.branch,
                            path: q('gettype') === "post" ? "/source/_posts/" : "/source/_drafts/"
                        })
                    })
                case 'list':
                    return gres({
                        ok: 1,
                        data: await hexo.app.list({
                            token: globalvar.hexoConfig.token,
                            repo: globalvar.hexoConfig.repo,
                            branch: globalvar.hexoConfig.branch,
                            path: q('gettype') === "post" ? "/source/_posts/" : "/source/_drafts/"
                        })
                    })
                case 'download':
                    return gres({
                        ok: 1,
                        data: await hexo.app.download({
                            token: globalvar.hexoConfig.token,
                            repo: globalvar.hexoConfig.repo,
                            branch: globalvar.hexoConfig.branch,
                            path: q('path')
                        })
                    })
                case 'upload':
                    return gres({
                        ok: 1,
                        data: await hexo.app.upload({
                            token: globalvar.hexoConfig.token,
                            repo: globalvar.hexoConfig.repo,
                            branch: globalvar.hexoConfig.branch,
                            path: q('path'),

                            content: req.body
                        })
                    })
                case 'delete':
                    return gres({
                        ok: 1,
                        data: await hexo.app.delete({
                            token: globalvar.hexoConfig.token,
                            repo: globalvar.hexoConfig.repo,
                            branch: globalvar.hexoConfig.branch,
                            path: q('path')
                        })
                    })
                case 'move':
                    return gres({
                        ok: 1,
                        data: await github.file.move({
                            token: globalvar.hexoConfig.token,
                            repo: globalvar.hexoConfig.repo,
                            branch: globalvar.hexoConfig.branch,
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
            return gres({
                ok: gauth.gcheck(
                    globalvar.basicConfig.key,
                    globalvar.basicConfig.user,
                    globalvar.basicConfig.pass,
                    globalvar.sign
                ),
                data: globalvar.sign
            })
        case 'config':
            if (!globalvar.admin) return gres({ ok: 0 })

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
                install: globalvar.install,
                admin: globalvar.admin,
                version: '0.0.1'
            })
    }
}
export default handle