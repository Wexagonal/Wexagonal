import path from 'path'

import {fileURLToPath} from 'url';

const __filename = fileURLToPath(import.meta.url);

// 👇️ "/home/john/Desktop/javascript"
const __dirname = path.dirname(__filename);
console.log('directory-name 👉️', __dirname);
export default {
    entry: './api/webworker.js',
    externals: {
        'node-fetch': 'fetch'
        
    },
    //webpack不压缩混淆
        
     optimization: {
         minimize: false
     },
    output: {
        path: path.resolve(__dirname, './dist'),
        filename: 'Wexagonal_CloudFlareWorker_Launcher.js',
    }
}