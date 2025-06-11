const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, 'users.json');

// Load users from file
let USERS = [];
try {
  if (fs.existsSync(DATA_FILE)) {
    USERS = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  }
} catch (err) {
  console.error("Failed to read user data:", err);
}

// Save users to file
function saveUsersToFile() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(USERS, null, 2));
}

function getUserByEmail(email) {
  return USERS.find((user) => user.email === email);
}

function getUserById(id) {
  return USERS.find((user) => user.id === id);
}

function createUser(id, email, passKey) {
  USERS.push({ id, email, passKey, wallet: null });
  saveUsersToFile();
}

function updateUserCounter(id, counter) {
  const user = USERS.find((user) => user.id === id);
  if (user && user.passKey) {
    user.passKey.counter = counter;
    saveUsersToFile();
  }
}

function updateUserWallet(id, walletData) {
  const user = USERS.find((user) => user.id === id);
  if (user) {
    user.wallet = walletData;
    saveUsersToFile();
    return user;
  }
  return null;
}

function addUserDelegate(id, delegateData) {
  const user = USERS.find((user) => user.id === id);
  if (user) {
    user.delegateData = delegateData;
    saveUsersToFile();
    return user;
  }
  return null;
}

module.exports = {
  getUserByEmail,
  getUserById,
  createUser,
  updateUserCounter,
  updateUserWallet,
  addUserDelegate,
};
