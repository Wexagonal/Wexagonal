
import cons from './../../src/cons.js'
import fetch from "node-fetch"
export const HTTP = async (config) => {
    const url = new URL(config.endpoint)
    url.searchParams.set('token', config.token)
    let res = ""
    return async (namespace) => {
        const t1 = new Date().getTime();
        url.searchParams.set("namespace", namespace)
        return {
            read: async (key) => {
                url.searchParams.set('action', 'read')
                url.searchParams.set('config', JSON.stringify({ key: key }))
                const res = await (await fetch(url)).json()
                cons.i(`数据库 读取 耗时: ${new Date().getTime() - t1}ms`)
                return res.data
            },
            write: async (key, value) => {
                url.searchParams.set('action', 'write')
                url.searchParams.set('config', JSON.stringify({ key: key, value: value }))
                const res = await (await fetch(url)).json()
                cons.i(`数据库 写入 耗时: ${new Date().getTime() - t1}ms`)
                return res.ok
            },
            delete: async (key) => {
                url.searchParams.set('action', 'delete')
                url.searchParams.set('config', JSON.stringify({ key: key }))
                const res = await (await fetch(url)).json()
                cons.i(`数据库 删除 耗时: ${new Date().getTime() - t1}ms`)
                return res.ok
            },
            set: async (data) => {
                url.searchParams.set('action', 'set')
                url.searchParams.set('config', JSON.stringify(data))
                const res = await (await fetch(url)).json()
                cons.i(`数据库 设置 耗时: ${new Date().getTime() - t1}ms`)
                return res.ok
            },
            list: async () => {
                url.searchParams.set('action', 'list')
                const res = await (await fetch(url)).json()
                cons.i(`数据库 列表 耗时: ${new Date().getTime() - t1}ms`)
                return res.data
            },
            keys: async () => {
                url.searchParams.set('action', 'keys')
                const res = await (await fetch(url)).json()
                cons.i(`数据库 keys 耗时: ${new Date().getTime() - t1}ms`)
                return res.data
            },
            values: async () => {
                url.searchParams.set('action', 'values')
                const res = await (await fetch(url)).json()
                cons.i(`数据库 values 耗时: ${new Date().getTime() - t1}ms`)
                return res.data
            }


        }
    }
}

export default HTTP