import github from './github.js'

import jsyaml from 'js-yaml'

const hexo = {
    app: {
        count: async (config) => {
            const res = await hexo.app.list(config)
            return res.length
        },
        list: async (config) => {
            const res = await github.file.list_all(config)
            const datalist = (list) => {
                let res = []
                for (let i in list) {
                    if (list[i].type == "file" && list[i].name.match(/\.md$/g)) {
                        res.push(list[i].path)
                    }
                    if (list[i].type == 'dir') {
                        res.push.apply(res, datalist(list[i].data))
                    }
                }
                return res
            }
            return datalist(res.data)

        },
        download: async (config) => {

            //base64 encode 
            //return Buffer.from(await github.file.download(config)).toString('base64')
            return github.file.download(config)

        },
        upload: async (config) => {
            const res = await github.file.upload(config)
            return res
        },
        delete: async (config) => {
            const res = await github.file.delete(config)
            return res
        },
        check_run: async (config) => {
            const res = (await github.run.list(config))["data"]
            if (res.workflow_runs.length == 0) {
                return []
            }
            for(let i in res.workflow_runs){
                if(res.workflow_runs[i].name == config.name){
                    return res.workflow_runs[i]
                }
            }
            return []
            
        }

    },


    check: async (config) => {

        let hres = {
            ok: 0,
            hexo: 0,
            indexhtml: 0,
            theme: 0,
            source: 0,
            config: {},
            repo: {

            }
        }
        config.username = config.repo.split('/')[0]
        config.reponame = config.repo.split('/')[1]
        let res = await github.repo.list(config)
        if (!res.ok) {
            return hres
        }
        if (!res.repos.length) {
            return hres
        }
        for (let i in res.repos) {
            if (res.repos[i].name == config.reponame) {
                hres.repo.private = res.repos[i].private
                hres.repo.permissions = res.repos[i].permissions
                hres.repo.disabled = res.repos[i].disabled ? 1 : 0
                hres.repo.archived = res.repos[i].archived ? 1 : 0
                break
            }
        }

        config.path = '/'
        res = await github.file.list(config)
        const list_cache = res
        for (var i in res.data) {
            if (res.data[i].name == 'index.html' && res.data[i].type === 'file') hres.indexhtml = 1
            if (res.data[i].name == 'source' && res.data[i].type === 'dir') hres.source = 1
            if (res.data[i].name == 'theme' && res.data[i].type === 'dir') hres.theme = 1
            if (res.data[i].name == 'package.json' && res.data[i].type === 'file') hres.pack = 1
            if (res.data[i].name == '_config.yml' && res.data[i].type === 'file') hres.config.hexo = '/_config.yml'
           


        }
        if (hres.config.hexo) {
            config.path = '/'
            config.filename = '_config.yml'
            res = await github.file.download(config)
            hres.theme = jsyaml.load(res).theme
            for (var i in list_cache.data) {
                if (list_cache.data[i].name == `_config.${hres.theme}.yml` && list_cache.data[i].type == 'file') {
                    hres.config.theme = `_config.${hres.theme}.yml`
                    break
                }
            }
            config.path = "/themes/"
            res = await github.file.list(config)

            for (var i in res.data) {
                if (res.data[i].name === hres.theme && res.data[i].type === 'dir') {
                    config.path = "/themes/" + hres.theme + "/"
                    res = await github.file.list(config)
                    for (var j in res.data) {
                        if (res.data[j].name == '_config.yml' && res.data[j].type === 'file') {
                            hres.config.theme = `/themes/${hres.theme}/_config.yml`
                        }
                    }
                    break
                }
            }

        }
        config.path = '/'
        config.filename = "package.json"
        res = await github.file.download(config)
        if (!res) return hres

        let pack = (() => { try { return JSON.parse(res) } catch (e) { return {} } })()
        if (!pack) return hres
        if (pack.hexo) {
            if (pack.hexo.version) {
                hres.hexo = 1
                hres.hexo_version = pack.hexo.version
            }
        }
        if (pack.dependencies) {
            if (pack.dependencies.hexo) {
                hres.hexo = 1
                hres.hexo_version = pack.dependencies.hexo
            }
        }
        if (!!hres.hexo && !!hres.config.hexo) {
            if (!!hres.theme && !!hres.config.theme) {
                if (!!hres.source && !!hres.pack && !!hres.hexo_version) {

                    if (!!hres.repo.permissions.push) {
                        hres.ok = 1
                    }
                }
            }
        }
        return hres

    }
}

export default hexo