const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const db = require("./db");

const app = express();
app.use(express.json());

// ✅ Sert les fichiers statiques depuis le dossier "frontend"
app.use(express.static(path.join(__dirname, "frontend")));

// 🔐 Fonction utilitaire : hash du mot de passe
function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

// 🔐 Chiffrement AES
function encrypt(text, password) {
  const key = crypto.createHash("sha256").update(password).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return { iv: iv.toString("hex"), data: encrypted };
}

// 🔐 Déchiffrement AES
function decrypt(encrypted, password, iv) {
  const key = crypto.createHash("sha256").update(password).digest();
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    key,
    Buffer.from(iv, "hex")
  );
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// ✅ Route GET pour afficher create.html
app.get("/create", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "create.html"));
});

// ✅ Route GET pour afficher release.html dynamiquement
app.get("/release/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "release.html"));
});

// ✅ Endpoint POST pour créer un message sécurisé
app.post("/create", (req, res) => {
  const { password, content, expireMinutes, maxViews } = req.body;
  if (!password || !content) {
    return res.status(400).json({ error: "Password and content required" });
  }

  const id = uuidv4();
  const hash = hashPassword(password);
  const encrypted = encrypt(content, password);

  // Valeurs par défaut : 5 minute et 1 vue
  const minutes = expireMinutes && Number(expireMinutes) > 0 ? Number(expireMinutes) : 5;
  const expiresAt = new Date(Date.now() + minutes * 60000).toISOString();


  const views = maxViews && Number(maxViews) > 0 ? Number(maxViews) : 1;

  db.run(
    "INSERT INTO messages (id, password_hash, content, expires_at, max_views, views_remaining) VALUES (?, ?, ?, ?, ?, ?)",
    [id, hash, JSON.stringify(encrypted), expiresAt, views, views],
    (err) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json({ link: `http://localhost:3000/release/${id}` });
    }
  );
});
app.post("/release/:id", (req, res) => {
  const { password } = req.body;
  const { id } = req.params;

  db.get("SELECT * FROM messages WHERE id = ?", [id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: "Not found" });

    // Vérifier expiration
    if (row.expires_at && new Date(row.expires_at) < new Date()) {
      db.run("DELETE FROM messages WHERE id = ?", [id]);
      return res.status(410).json({ error: "Message expired" });
    }

    // Vérifier nombre de vues restantes
    if (row.views_remaining !== null && row.views_remaining <= 0) {
      db.run("DELETE FROM messages WHERE id = ?", [id]);
      return res.status(410).json({ error: "Message view limit reached" });
    }

    // Vérifier mot de passe
    if (hashPassword(password) !== row.password_hash) {
      return res.status(403).json({ error: "Wrong password" });
    }

    // Déchiffrement
    const { iv, data } = JSON.parse(row.content);
    let decrypted;
    try {
      decrypted = decrypt(data, password, iv);
    } catch {
      return res.status(500).json({ error: "Decryption failed" });
    }

    // Mise à jour des vues restantes
    if (row.views_remaining !== null) {
      const remaining = row.views_remaining - 1;

      if (remaining <= 0) {
        db.run("DELETE FROM messages WHERE id = ?", [id], () => {
          return res.json({ content: decrypted, expiresAt: row.expires_at });
        });
      } else {
        db.run("UPDATE messages SET views_remaining = ? WHERE id = ?", [remaining, id], () => {
          return res.json({ content: decrypted, expiresAt: row.expires_at });
        });
      }
    } else {
      db.run("DELETE FROM messages WHERE id = ?", [id], () => {
        return res.json({ content: decrypted, expiresAt: row.expires_at });
      });
    }
  });
});





// ✅ Démarrage du serveur
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Serveur lancé sur http://localhost:${PORT}`);
});
