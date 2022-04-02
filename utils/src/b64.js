import globalvar from "./globalvar.js"
const b64 = {
    en:(data)=>{
        if(typeof Buffer !== 'undefined'){
            return Buffer.from(data).toString('base64')
        }else{
            return btoa(data)
        }
    },
    de:(data)=>{
        if(typeof Buffer !== 'undefined'){
            return Buffer.from(data,'base64').toString()
        }else{
            return atob(data)
        }
    },
    de_binarray:(data)=>{
        if(typeof Buffer !== 'undefined'){
            return Buffer.from(data, 'base64').toString('binary')
        }else{
            return atob(data)
        }
    },
    de_blob:(data)=>{
        const byteString = b64.de_binarray(data)
        const arrayBuffer = new ArrayBuffer(byteString.length);
        const intArray = new Uint8Array(arrayBuffer);
        for (let i = 0; i < byteString.length; i++) {
            intArray[i] = byteString.charCodeAt(i);
        }
        return new globalvar.Blob([intArray], { type: 'image/png' });
    }
}

export default b64;