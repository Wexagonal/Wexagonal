// read write delete keys values list

import { MongoClient } from "mongodb";
import consola from "consola";

export const MONGODB = async(config) => {
  const endpoint = config.endpoint;

  const client = await MongoClient.connect(endpoint, { useNewUrlParser: true, useUnifiedTopology: true });
  const db = await client.db("WexagonalDB");

  return async(namespace) => {
    const t1 = new Date().getTime();

    setTimeout(async() => {
      await client.close();
    }, 5000);
    return {
      read: async(key) => {
        const data = await db.collection(namespace).findOne({ key });
        consola.info(`数据库 读取 耗时: ${new Date().getTime() - t1}ms`);
        return data ? data.value : null;
      },
      write: async(key, value) => {
        await db.collection(namespace).updateOne({ key }, { $set: { value } }, { upsert: true });
        consola.info(`数据库 写入 耗时: ${new Date().getTime() - t1}ms`);
        return true;
      },
      delete: async(key) => {
        await db.collection(namespace).deleteOne({ key });
        consola.info(`数据库 删除 耗时: ${new Date().getTime() - t1}ms`);
        return true;
      },
      set: async(data) => {
        await db.collection(namespace).deleteMany({});
        await db.collection(namespace).insertMany([data]);
        consola.info(`数据库 设置 耗时: ${new Date().getTime() - t1}ms`);
        return true;
      },
      list: async() => {
        const res = await db.collection(namespace).find().toArray();
        const data = {};
        for (const i in res)
          data[res[i].key] = res[i].value;

        consola.info(`数据库 列表 耗时: ${new Date().getTime() - t1}ms`);
        return data;
      },
      keys: async() => {
        return await db.collection(namespace).find().toArray().then(data => data.map(d => d.key));
      },
      values: async() => {
        return await db.collection(namespace).find().toArray().then(data => data.map(d => d.value));
      },
      close: async() => {
        consola.info(`数据库断开长连接 ${new Date().getTime().toLocaleString()}`);
        await client.close();
      },

    };
  };
};
export default MONGODB;
