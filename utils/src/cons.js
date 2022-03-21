const cons = {
    s:(msg)=>{
        console.log(`[成功] ${msg}`);
    },
    e:(msg)=>{
        console.log(`[失败] ${msg}`);
    },
    w:(msg)=>{
        console.log(`[警告] ${msg}`);
    },
    i:(msg)=>{
        console.log(`[信息] ${msg}`);
    }
}

export default cons;