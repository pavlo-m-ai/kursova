const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const { findUserByEmail, addUser } = require("./db");

// Завантажуємо змінні з .env
dotenv.config();

console.log("🔹 Перевірка SECRET_KEY:", process.env.SECRET_KEY); // Перевіряємо, чи .env завантажився

const SECRET_KEY = process.env.SECRET_KEY;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

if (!SECRET_KEY) {
  throw new Error("❌ SECRET_KEY не знайдено в .env файлі! Перевірте .env та перезапустіть сервер.");
}

// Функція реєстрації нового користувача
function registerUser(email, password) {
  if (findUserByEmail(email)) {
    throw new Error("❌ Цей email вже зареєстрований!");
  }

  const newUser = addUser(email, password);
  const accessToken = jwt.sign({ userId: newUser.id }, SECRET_KEY, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ userId: newUser.id }, SECRET_KEY, { expiresIn: "7d" });

  return { user: newUser, accessToken, refreshToken };
}

// Функція логіну
function login(email, password) {
  const user = findUserByEmail(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    throw new Error("❌ Невірний email або пароль");
  }

  const accessToken = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "7d" });

  return { accessToken, refreshToken };
}

module.exports = { login, registerUser };
