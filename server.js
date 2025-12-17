const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database("./database.sqlite");

db.run(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)
`);

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users(username, password) VALUES (?, ?)",
    [username, hash],
    err => {
      if (err) return res.json({ message: "User exists" });
      res.json({ message: "Registered successfully" });
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (!user) return res.json({ message: "Invalid user" });

      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.json({ message: "Wrong password" });

      res.json({ message: "Login success" });
    }
  );
});

app.listen(3000, () => console.log("Server running on port 3000"));
