import http from "http";
import consola from "consola";
import { HTTP, MONGODB, getEnv, handle } from "../utils/index.js";

const NODE_DEFAULT_PORT = getEnv("PORT") || 4000;
consola.info("以Node形式启动Wexagonal");
consola.info(`监听地址为：0.0.0.0:${NODE_DEFAULT_PORT}`);
http.createServer(async(req, res) => {
  const t1 = new Date().getTime();
  const body = new Promise((resolve) => {
    const data = [];
    req.on("data", (chunk) => {
      data.push(chunk);
    });
    req.on("end", () => {
      resolve(Buffer.concat(data).toString());
    });
  });
  const PUBLIC_URL = new URL(req.url, "http://localhost:4000");
  PUBLIC_URL.searchParams.set("token", "HIDE_TOKEN");
  consola.info(`捕获请求: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()}`);
  const request = {
    body: await body,
    method: req.method,
    url: req.url,
    headers: req.headers,
  };
  handle(request, (() => {
    const config = (() => {
      try { return JSON.parse(getEnv("DB_CONFIG")); }
      catch (e) { consola.error("无法解析数据库配置!"); return null; }
    })();
    if (!config) return null;
    switch (config.type) {
      case "HTTP":
        return HTTP(config);
      case "MONGODB":
        return MONGODB(config);
      default:
        return null;
    }
  })()).then((rep) => {
    res.writeHead(rep.status || 200, rep.headers);
    consola.success(`响应请求: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()} 耗时: ${new Date().getTime() - t1}ms`);
    res.end(rep.body);
  }).catch(() => {
    consola.error(`响应请求: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()} 耗时: ${new Date().getTime() - t1}ms`);
    res.writeHead(500);
    res.end();
  });
}).listen(NODE_DEFAULT_PORT);
