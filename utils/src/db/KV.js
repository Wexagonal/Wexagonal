/* global DB */

export const KV = (_config) => {
  return async(namespace) => {
    return {
      read: async(key) => {
        let db = await DB.get(namespace);
        if (!db) {
          db = {};
          await DB.put(namespace, JSON.stringify(db));
        }
        db = (() => {
          try { return JSON.parse(db); }
          catch (e) { return {}; }
        })();

        return db[key];
      },
      write: async(key, value) => {
        let db = await DB.get(namespace);
        if (!db) {
          db = {};
          await DB.put(namespace, JSON.stringify(db));
        }
        db = (() => {
          try { return JSON.parse(db); }
          catch (e) { return {}; }
        })();
        db[key] = value;
        await DB.put(namespace, JSON.stringify(db));
        return true;
      },
      set: async(data) => {
        data = typeof data == "string" ? JSON.parse(data) : data;
        await DB.put(namespace, JSON.stringify(data));
        return true;
      },
      delete: async(key) => {
        let db = await DB.get(namespace);
        if (!db) {
          db = {};
          await DB.put(namespace, JSON.stringify(db));
        }
        db = (() => {
          try { return JSON.parse(db); }
          catch (e) { return "{}"; }
        })();
        delete db[key];
        await DB.put(namespace, JSON.stringify(db));
        return true;
      },
      list: async() => {
        let db = await DB.get(namespace);
        if (!db) {
          db = {};
          await DB.put(namespace, JSON.stringify(db));
        }
        db = (() => {
          try { return JSON.parse(db); }
          catch (e) { return "{}"; }
        })();
        return db;
      },
      keys: async() => {
        let db = await DB.get(namespace);
        if (!db) {
          db = {};
          await DB.put(namespace, JSON.stringify(db));
        }
        db = (() => {
          try { return JSON.parse(db); }
          catch (e) { return "{}"; }
        })();
        return Object.keys(db);
      },
      values: async() => {
        let db = await DB.get(namespace);
        if (!db) {
          db = {};
          await DB.put(namespace, JSON.stringify(db));
        }
        db = (() => {
          try { return JSON.parse(db); }
          catch (e) { return "{}"; }
        })();
        return Object.values(db);
      },
    };
  };
};
export default KV;
