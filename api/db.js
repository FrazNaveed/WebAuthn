const USERS = [];

function getUserByEmail(email) {
  return USERS.find((user) => user.email === email);
}

function getUserById(id) {
  return USERS.find((user) => user.id === id);
}

function createUser(id, email, passKey) {
  USERS.push({ id, email, passKey, wallet: null }); // Initialize wallet as null
}

function updateUserCounter(id, counter) {
  const user = USERS.find((user) => user.id === id);
  user.passKey.counter = counter;
}

function updateUserWallet(id, walletData) {
  const user = USERS.find((user) => user.id === id);
  if (user) {
    user.wallet = walletData; // Overwrite or set wallet data
    console.log(USERS);
    return user;
  }
  return null; // User not found
}

module.exports = {
  getUserByEmail,
  getUserById,
  createUser,
  updateUserCounter,
  updateUserWallet,
};
