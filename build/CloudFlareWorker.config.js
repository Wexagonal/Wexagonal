import path from 'path'

import {fileURLToPath} from 'url';
//webpack-bundle-analyzer
import { BundleAnalyzerPlugin } from 'webpack-bundle-analyzer';
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
     plugins:[
            new BundleAnalyzerPlugin({
                analyzerMode: 'static',
                openAnalyzer: false,
                reportFilename: './report.html'
            })
     ],
    output: {
        path: path.resolve(__dirname, './dist'),
        filename: 'Wexagonal_CloudFlareWorker_Launcher.js',
    }
}