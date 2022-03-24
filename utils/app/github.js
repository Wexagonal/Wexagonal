import fetch from 'node-fetch'
import cons from './../src/cons.js'
const end = async (path, token, config) => {
    config = config || {}
    const url = new URL('https://api.github.com' + path.replace(/\/+/g, '/'))
    cons.i(`Github模块请求地址: ${url}`)
    if (config.init) {
        //key value
        for (let key in config.init) {
            url.searchParams.set(key, config.init[key])
        }
    }
    if (!!config.branch) {
        url.searchParams.set('ref', config.branch)
    }
    return fetch(url, {
        headers: {
            'Authorization': `token ${token}`,
            'user-agent': 'Wexagonal'
        },
        method: !!config.method ? config.method : 'GET',
        body: !!config.body && config.method !== 'GET' ? config.body : null
    }).then(res => {

        if (config.type === 'text') {
            return res.text()
        } else {
            return res.json()
        }
    })
}
const github = {
    user: {
        auth: async (config) => {
            const res = await end('/user', config.token)
            if (!res.login) {
                return { ok: 0 }
            }
            return {
                ok: 1,
                loginname: res.login,
                username: res.name,
                usertype: res.type,

            }
        },
        name: async (config) => {
            const res = await github.user.auth(config)
            return res.loginname
        }

    },
    repo: {
        list: async (config) => {
            config.username = config.username || await github.user.name(config)
            const res = await (async () => {
                let page = 1
                let endres;
                const nres = []
                while (1) {
                    endres = await end('/user/repos', config.token, {
                        init: {
                            type: 'all',
                            sort: 'updated',
                            per_page: 100,
                            page: page
                        }
                    })
                    for (let i = 0; i < endres.length; i++) {
                        if (!!config.org || (endres[i].owner.login === config.username && !config.org)) {
                            nres.push(endres[i])
                        }
                    }
                    if (endres.length < 100) {
                        return nres
                    }
                    page++
                }
            })()
            if (!res) {
                return { ok: 0 }
            }
            if (config.org) {
                return { ok: 1, repos: res }
            }
            return { ok: 1, repos: res.filter(repo => repo.owner.login == config.username) }
        }
    },
    branch: {
        list: async (config) => {
            const res = await end('/repos/' + config.repo + '/branches', config.token, config)

            if (!res || !res.length) {
                return { ok: 0 }
            }
            return { ok: 1, branches: res }
        },
        default: async (config) => {
            const res = await github.branch.list(config)
            if (!res.ok) {
                return null
            }
            return res.branches[0].name
        }
    },
    file: {
        move: async (config) => {
            //将config.path中的文件先github.file.download下载 而后github.file.upload上传,最后删除github.file.download下载的文件
            config.download_type = "arraybuffer"
            const file = await github.file.download(config)
            config.oldpath = config.path
            config.path = config.newpath
            //config.content = Buffer.toString(file, 'base64')
            //将file从arraybuffer转为base64
            config.content = Buffer.from(file).toString('base64')
            const res = await github.file.upload(config, file)
            if (res.ok) {
                config.path = config.oldpath
                await github.file.delete(config)
            }
            return res

        },
        list: async (config) => {
            const res = await end('/repos/' + config.repo + '/contents/' + config.path, config.token, config)

            if (!res || !res.length) {
                return { ok: 0 }
            }
            return { ok: 1, data: res }
        },
        list_all: async (config) => {
            //深搜,每次获取一个目录下的所有文件,如果为文件夹,则进入搜索
            const res = await github.file.list(config)
            if (!res.ok) {
                return { ok: 0 }
            }
            if (!res.data || !res.data.length) {
                return { ok: 0 }
            }
            for (var i in res.data) {
                if (res.data[i].type == 'dir') {
                    const res2 = await github.file.list_all({
                        token: config.token,
                        repo: config.repo,
                        path: res.data[i].path + '/'
                    })
                    if (!res2.ok) {
                        return { ok: 0 }
                    }
                    res.data[i].data = res2.data
                }
            }
            return { ok: 1, data: res.data }
        },
        info: async (config) => {

            config.filename = config.filename ? config.filename : config.path.split('/').pop()
            config.pathname = config.pathname ? config.pathname : config.path.split('/').slice(0, -1).join('/') + "/"
            const res = await github.file.list({
                token: config.token,
                repo: config.repo,
                path: config.pathname
            })

            if (!res.ok || !res.data.length) {
                return { ok: 0 }
            }

            for (var i in res.data) {
                if (res.data[i].name == config.filename) {
                    return { ok: 1, data: res.data[i] }
                }
            }

            return { ok: 0 }
        },
        sha: async (config) => {
            const res = await github.file.info(config)
            if (!res.ok) {
                return { ok: 0 }
            }
            return { ok: 1, data: res.data.sha }
        }
        ,
        download: async (config) => {
            //getinfo to download
            const res = await github.file.info(config)
            if (!res.ok) {
                return null
            }
            return fetch(res.data.download_url).then(res => {
                if (config.download_type == "arraybuffer") {
                    return res.arrayBuffer()
                }

                return res.text()
            }).catch(err => {
                return null
            })
        },
        upload: async (config) => {

            config.filename = config.path.split('/').pop()
            config.pathname = config.path.split('/').slice(0, -1).join('/') + "/"
            const res = await end('/repos/' + config.repo + '/contents/' + config.path, config.token, {
                method: 'PUT',
                body: JSON.stringify({
                    message: config.message ? config.message : 'Wexagonal Upload at ' + new Date().toLocaleString(),
                    content: config.content,
                    branch: config.branch ? config.branch : await github.branch.default(config),
                    sha: config.sha ? config.sha : (await github.file.sha(config)).data,
                })
            })
            if (!res.content) {
                return res
            }
            return { ok: 1, content: res.content }
        },
        delete: async (config) => {

            config.filename = config.path.split('/').pop()
            config.pathname = config.path.split('/').slice(0, -1).join('/') + "/"
            const res = await end('/repos/' + config.repo + '/contents/' + config.pathname + config.filename, config.token, {
                method: 'DELETE',
                body: JSON.stringify({
                    message: config.message ? config.message : 'Wexagonal Delete at ' + new Date().toLocaleString(),
                    sha: (await github.file.sha(config)).data,
                })
            })
            return res
        }
    },
    webhook: {
        list: async (config) => {
            const res = await end('/repos/' + config.repo + '/hooks', config.token)
            if (!res || !res.length) {
                return { ok: 0 }
            }
            return { ok: 1, hooks: res }
        },
        edit: async (config) => {
            const res = await end('/repos/' + config.repo + '/hooks/' + config.id, config.token, config)
            if (!res) {
                return { ok: 0 }
            }
            return { ok: 1, hook: res }
        }
    },
    workflow: {
        list: async (config) => {
            const res = await end('/repos/' + config.repo + '/actions/workflows', config.token, config)

            if (!res) {
                return { ok: 0 }
            }
            return { ok: 1, data: res }
        },
        info: async (config) => {
            const res = await github.workflow.list(config)
            if (!res.ok) {
                return { ok: 0 }
            }
            for (var i in res.data.workflows) {
                if (res.data.workflows[i].name == config.name) {
                    return { ok: 1, data: res.data.workflows[i] }
                }
            }
            return { ok: 0 }
        },
        path: async (config) => {
            const res = await github.workflow.list(config)
            if (!res.ok) {
                return null
            }
            return res.data.workflows.filter(workflow => workflow.name == config.workflow)[0].path

        },
        download: async (config) => {
            config.workflow_path = await github.workflow.path(config)
            config.filename = config.workflow_path.split('/').pop()
            config.path = config.workflow_path.replace(config.filename, '')
            return github.file.download(config)

        },
        upload: async (config) => {
            config.path = await github.workflow.path(config)
            config.filename = config.path.split('/').pop()
            config.pathname = config.path.replace(config.filename, '')
            return github.file.upload(config)
        },
        dispatch: async (config) => {
            const res = await end('/repos/' + config.repo + '/actions/workflows/' + await (async (config) => {
                const res = await github.workflow.info(config)
                //console.log(res)
                if (!res.ok) {
                    return null
                }
                return res.data.id
            })(config) + '/dispatches', config.token, {
                method: 'POST',
                body: JSON.stringify({
                    ref: config.branch
                }),
                type: 'text'
            })
            return { ok: 1, content: res.content }
        }
    },
    run: {
        info: async (config) => {
            const res = await github.run.list(config)
            if (!res.ok) {
                return { ok: 0 }
            }
            for (var i in res.data.workflow_runs) {
                if (res.data.workflow_runs[i].name == config.name) {
                    return { ok: 1, data: res.data.workflow_runs[i] }
                }
            }
            return { ok: 0 }
        },
        list: async (config) => {
            const res = await end('/repos/' + config.repo + '/actions/runs', config.token, config)
            if (!res) {
                return { ok: 0 }
            }
            return { ok: 1, data: res }
        },
        cancel: async (config) => {
            const res = await end('/repos/' + config.repo + '/actions/runs/' + await (async (config) => {
                const res = await github.run.info(config)
                if (!res.ok) {
                    return null
                }
                return res.data.id
            })(config) + '/cancel', config.token, {
                method: 'POST'
            })
            if (!res) {
                return { ok: 0 }
            }
            return { ok: 1, data: res }
        }
    }

}

export default github