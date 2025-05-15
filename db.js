const bcrypt = require("bcryptjs");

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

module.exports = { users, findUserByEmail, addUser };
