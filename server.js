require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname + "/public"));

const users = [];
const blacklistedTokens = new Set(); // Чорний список токенів

// Реєстрація користувача
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (users.find((user) => user.email === email)) {
    return res.status(400).json({ message: "Користувач вже існує" });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ email, password: hashedPassword });
  res.json({ message: "Реєстрація успішна" });
});

// Логін
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((user) => user.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Невірний email або пароль" });
  }
  const token = jwt.sign({ email }, process.env.SECRET_KEY, { expiresIn: "1h" });
  res.json({ token });
});

// Вихід з акаунту (інвалідація токена)
app.post("/logout", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (token) {
    blacklistedTokens.add(token);
  }
  res.json({ message: "Ви вийшли з системи" });
});

// Отримання профілю
app.get("/profile", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token || blacklistedTokens.has(token)) {
    return res.status(401).json({ message: "Не авторизований або токен інвалідований" });
  }

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    res.json({ email: decoded.email });
  } catch {
    res.status(401).json({ message: "Недійсний токен" });
  }
});

// Запуск сервера
app.listen(process.env.PORT || 3000, () => {
  console.log("Сервер працює на http://localhost:3000");
});
