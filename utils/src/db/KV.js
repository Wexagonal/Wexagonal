import cons from '../cons.js'
export const KV = (config) => {
    return async (namespace) => {
        const t1 = new Date().getTime();
        return {
            read: async (key) => {

                let db = await DB.get(namespace)
                if (!db) {
                    db = {}
                    await DB.put(namespace, JSON.stringify(db))
                }
                db = (() => { try { return JSON.parse(db) } catch (e) { return {} } })()
                
                cons.i(`数据库 读取 耗时: ${new Date().getTime() - t1}ms`)
                return db[key]
            },
            write: async (key, value) => {
                let db = await DB.get(namespace)
                if (!db) {
                    db = {}
                    await DB.put(namespace, JSON.stringify(db))
                }
                db = (() => { try { return JSON.parse(db) } catch (e) { return {} } })()
                db[key] = value
                await DB.put(namespace, JSON.stringify(db))
                cons.i(`数据库 写入 耗时: ${new Date().getTime() - t1}ms`)
                return true
            },
            set: async (data) => {
                data = typeof data == 'string' ? JSON.parse(data) : data
                await DB.put(namespace, JSON.stringify(data))
                cons.i(`数据库 设置 耗时: ${new Date().getTime() - t1}ms`)
                return true
            },
            delete: async (key) => {
                let db = await DB.get(namespace)
                if (!db) {
                    db = {}
                    await DB.put(namespace, JSON.stringify(db))
                }
                db = (() => { try { return JSON.parse(db) } catch (e) { return '{}' } })()
                delete db[key]
                await DB.put(namespace, JSON.stringify(db))
                cons.i(`数据库 删除 耗时: ${new Date().getTime() - t1}ms`)
                return true
            },
            list: async () => {
                let db = await DB.get(namespace)
                if (!db) {
                    db = {}
                    await DB.put(namespace, JSON.stringify(db))
                }
                db = (() => { try { return JSON.parse(db) } catch (e) { return '{}' } })()
                cons.i(`数据库 列表 耗时: ${new Date().getTime() - t1}ms`)
                return db
            },
            keys: async () => {
                let db = await DB.get(namespace)
                if (!db) {
                    db = {}
                    await DB.put(namespace, JSON.stringify(db))
                }
                db = (() => { try { return JSON.parse(db) } catch (e) { return '{}' } })()
                cons.i(`数据库 键列表 耗时: ${new Date().getTime() - t1}ms`)
                return Object.keys(db)
            },
            values: async () => {
                let db = await DB.get(namespace)
                if (!db) {
                    db = {}
                    await DB.put(namespace, JSON.stringify(db))
                }
                db = (() => { try { return JSON.parse(db) } catch (e) { return '{}' } })()
                cons.i(`数据库 值列表 耗时: ${new Date().getTime() - t1}ms`)
                return Object.values(db)
            }
        }
    }
}
export default KV