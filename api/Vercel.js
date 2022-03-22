import consola from "consola";
import { HTTP, MONGODB, getEnv, handle } from "../utils/index.js";

consola.info("以Vercel形式启动Wexagonal");
/**
 * @param {import('@vercel/node').VercelRequest} req
 * @param {import('@vercel/node').VercelResponse} res
 */
export default (req, res) => {
  const t1 = new Date().getTime();

  const PUBLIC_URL = new URL(req.url, "http://localhost:4000");
  PUBLIC_URL.searchParams.set("token", "HIDE_TOKEN");
  consola.info(`捕获请求: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()}`);
  const request = {
    body: req.body,
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
    for (const i in rep.headers)
      res.setHeader(i, rep.headers[i]);

    res.statusCode = rep.status || 200;
    consola.success(`响应请求: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()} 耗时: ${new Date().getTime() - t1}ms`);

    res.send(rep.body);
  }).catch((e) => {
    consola.error(`响应失败: ${PUBLIC_URL} 时间: ${new Date().toLocaleString()} 耗时: ${new Date().getTime() - t1}ms 错误原因: ${e}`);
    res.statusCode = 500;
    res.send();
  });
};
