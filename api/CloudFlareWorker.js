import { HTTP, KV, getEnv, handle } from "../utils/index.js";

// Import DB

const generate_response = async(req) => {
  const request = {
    body: await req.text(),
    method: req.method,
    url: req.url,
    headers: req.headers,
  };
  const res = await handle(request, (() => {
    const config = (() => {
      try { return JSON.parse(getEnv("DB_CONFIG")); }
      catch (e) { return null; }
    })();
    if (!config) return null;
    switch (config.type) {
      case "KV":
        return KV(config);
      case "HTTP":
        return HTTP(config);
      default:
        return null;
    }
  })());
  return new Response(res.body, {
    status: res.statusCode || 200,
    headers: res.headers,
  });
};

addEventListener("fetch", (event) => {
  event.respondWith(generate_response(event.request));
});
