const express = require("express");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

let users = [
  { id: 1, email: "user@example.com", password: bcrypt.hashSync("password123", 10) }
];

function findUserByEmail(email) {
  return users.find(user => user.email === email);
}

function addUser(email, password) {
  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = { id: users.length + 1, email, password: hashedPassword };
  users.push(newUser);
  return newUser;
}

function login(email, password) {
  const user = findUserByEmail(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    throw new Error("Невірний email або пароль");
  }
  const accessToken = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "7d" });
  return { accessToken, refreshToken };
}

function refresh(refreshToken) {
  try {
    const payload = jwt.verify(refreshToken, SECRET_KEY);
    const newAccessToken = jwt.sign({ userId: payload.userId }, SECRET_KEY, { expiresIn: "15m" });
    return { accessToken: newAccessToken };
  } catch {
    throw new Error("Невірний refresh token");
  }
}

function register(email, password, apiKey) {
  if (apiKey !== ADMIN_API_KEY) {
    throw new Error("У вас немає прав");
  }
  return addUser(email, password);
}

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.render("index");
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  try {
    const tokens = login(email, password);
    res.render("dashboard", { tokens });
  } catch (error) {
    res.render("index", { error: error.message });
  }
});

app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body;
  try {
    const newToken = refresh(refreshToken);
    res.json(newToken);
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

app.post("/register", (req, res) => {
  const { email, password, apiKey } = req.body;
  try {
    const newUser = register(email, password, apiKey);
    res.json({ message: "Користувач створений", user: newUser });
  } catch (error) {
    res.status(403).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Сервер працює на http://localhost:${PORT}`);
});
