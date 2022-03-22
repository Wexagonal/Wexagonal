import fetch, {
    Blob,
    blobFrom,
    blobFromSync,
    File,
    fileFrom,
    fileFromSync,
    FormData,
    Headers,
    Request,
    Response,

} from 'node-fetch'


const globalvar = {}
if (typeof self === 'undefined') {
    globalvar.FormData = FormData
    globalvar.Headers = Headers
    globalvar.Request = Request
    globalvar.Response = Response
    globalvar.fetch = fetch
    globalvar.Blob = Blob
    globalvar.blobFrom = blobFrom
    globalvar.blobFromSync = blobFromSync
    globalvar.File = File
    globalvar.fileFrom = fileFrom
    globalvar.fileFromSync = fileFromSync
    globalvar.FormData = FormData
    globalvar.Buffer = Buffer

} else {
    globalvar.FormData = self.FormData
    globalvar.Headers = self.Headers
    globalvar.Request = self.Request
    globalvar.Response = self.Response
    globalvar.fetch = self.fetch
    globalvar.Blob = self.Blob
    globalvar.blobFrom = self.blobFrom
    globalvar.blobFromSync = self.blobFromSync
    globalvar.File = self.File
    globalvar.fileFrom = self.fileFrom
    globalvar.fileFromSync = self.fileFromSync
    globalvar.FormData = self.FormData
    
    self.globalvar = globalvar
}

export default globalvar