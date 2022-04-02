import globalvar from "./globalvar.js";
const writelogs = async (type,action,data) =>{
    globalvar.wexaLog.push({
        time: new Date().getTime(),
        type: type,
        action: action,
        data: data
    })
    await globalvar.DB.SQL.write('wexaLog', globalvar.wexaLog)
}
export default writelogs