import gres from '../src/gres.js'
import github from './github.js'
import hexo from './hexo.js'
import jsyaml from 'js-yaml'
import globalvar from '../src/globalvar.js'
import { Base64 } from 'js-base64';
const tester = async (req, db) => {
    const urlObj = new URL(req.url, 'http://localhost')
    const q = key => {
        return urlObj.searchParams.get(key) || null
    }
    switch (q('init')) {
        case 'hexo':
            switch (q('action')) {
                case 'auth_user':
                    return gres(
                        await github.user.auth({ token: q('token') })
                    )
                    break;
                case 'list_repo':
                    return gres(
                        await github.repo.list({
                            token: q('token'),
                            username: q('username'),
                            org: Number(q('org'))
                        })
                    )
                case 'list_branches':
                    return gres(
                        await github.branch.list({
                            token: q('token'),
                            repo: q('repo')
                        }))
                case 'get_file_info':
                    return gres(
                        await github.file.info({
                            token: q('token'),
                            repo: q('repo'),
                            branch: q('branch'),
                            path: q('path'),
                            filename: q('filename')
                        }))
                case 'test_hexo':
                    return gres(
                        await hexo.check({
                            token: q('token'),
                            repo: q('repo'),
                            branch: q('branch')
                        })
                    )
                case 'list_workflow':
                    return gres(
                        await github.workflow.list({
                            token: q('token'),
                            repo: q('repo'),
                            branch: q('branch')
                        })
                    )
                case 'reset_workflow':
                    let wf = await github.workflow.download({
                        token: q('token'),
                        repo: q('repo'),
                        branch: q('branch'),
                        workflow: q('workflow')
                    })
                    wf = jsyaml.load(wf)
                    if(typeof wf.on === 'undefined' || typeof wf.on === "string") {
                        wf.on = []
                    }
                    if (q('onlydispatch')==='true') {
                        console.log('onlydispatch')
                        wf.on = ["workflow_dispatch"]
                    } else {
                        
                        if (wf.on.indexOf("workflow_dispatch")===-1) {
                            wf.on.push("workflow_dispatch")
                        }

                    }
                    wf = jsyaml.dump(wf)
                    let up_wf = await github.workflow.upload({
                        token: q('token'),
                        repo: q('repo'),
                        branch: q('branch'),
                        workflow: q('workflow'),
                        content: Base64.encode(wf)

                    })
                    if (up_wf.ok) return gres({ ok: 1 })
                    
                    return gres({ ok: 1 })
            }
            break;
    }
}
export default tester