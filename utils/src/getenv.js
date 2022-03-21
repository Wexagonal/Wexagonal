//获得 全局变量 环境变量
const getEnv = (key) => {
    if (typeof process !== 'undefined') {
        if (typeof process.env !== 'undefined') {
            if (!!process.env[key]) {
                return process.env[key]
            }
        }
    }
    if (typeof self !== 'undefined') {
        if (!!self[key]) {
            return self[key]
        }
    }
    return null

}
export default getEnv