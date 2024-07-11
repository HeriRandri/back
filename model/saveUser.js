const fs = require("fs");
const path = require("node:path");

const filePath = path.join(__dirname, "Utilisateur.json");

const saveUser = (user) => {
  let users = [];
  if (fs.existsSync(filePath)) {
    users = JSON.parse(fs.readFileSync(filePath)); // Correction ici
  }
  users.push(user);
  fs.writeFileSync(filePath, JSON.stringify(users, null, 2));
};

const getUsers = () => {
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath));
  }
  return [];
};

const findUseById = (email) => {
  const users = getUsers();
  return users.find((user) => user.email === email);
};

module.exports = { saveUser, getUsers, findUseById };
