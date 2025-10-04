const sqlite3 = require("sqlite3").verbose();
const fs = require("fs");

const dbFile = "./data.sqlite";

if (!fs.existsSync(dbFile)) {
  fs.writeFileSync(dbFile, "");
}

const db = new sqlite3.Database(dbFile);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      max_views INTEGER,
      views_remaining INTEGER
    )
  `);
});


module.exports = db;
