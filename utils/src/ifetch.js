import fetch from "node-fetch";

const ifetch = (url, init) => {
  if (!Promise.any) {
    Promise.any = (promises) => {
      return new Promise((resolve, reject) => {
        promises.forEach((promise) => {
          promise.then(resolve).catch(reject);
        });
      });
    };
  }
  if (typeof (url) == "object")
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    return Promise.any(url.map(u => ifetch(u, init)));

  else
    return fetch(url, init);
};
