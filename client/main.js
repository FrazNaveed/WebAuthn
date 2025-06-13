import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";

const signupButton = document.querySelector("[data-signup]");
const loginButton = document.querySelector("[data-login]");
const walletButton = document.querySelector("[data-create-wallet]");
const transactionButton = document.querySelector("[data-send-transaction]");
const enableDelegateButton = document.querySelector("[data-enable-delegate]");
const eipTxButton = document.querySelector("[data-eip-transaction]");
const selfcallButton = document.querySelector("[data-selfcall]");

const emailInput = document.querySelector("[data-email]");
const modal = document.querySelector("[data-modal]");
const closeButton = document.querySelector("[data-close]");

signupButton.addEventListener("click", signup);
loginButton.addEventListener("click", login);
walletButton.addEventListener("click", createwallet);
transactionButton.addEventListener("click", sendTransaction);
enableDelegateButton.addEventListener("click", enableDelegate);
eipTxButton.addEventListener("click", eipTx);
selfcallButton.addEventListener("click", selfcall);

closeButton.addEventListener("click", () => modal.close());

const SERVER_URL = "http://localhost:3000";

async function signup() {
  const email = emailInput.value;

  // 1. Get challenge from server
  const initResponse = await fetch(
    `${SERVER_URL}/init-register?email=${email}`,
    { credentials: "include" }
  );
  const options = await initResponse.json();
  if (!initResponse.ok) {
    showModalText(options.error);
  }

  // 2. Create passkey
  const registrationJSON = await startRegistration(options); // navigator.credentials.create()
  console.log(registrationJSON);

  // 3. Save passkey in DB
  const verifyResponse = await fetch(`${SERVER_URL}/verify-register`, {
    credentials: "include",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(registrationJSON),
  });

  const verifyData = await verifyResponse.json();
  if (!verifyResponse.ok) {
    showModalText(verifyData.error);
  }
  if (verifyData.verified) {
    showModalText(`Successfully registered ${email}`);
  } else {
    showModalText(`Failed to register`);
  }
}

async function login() {
  const email = emailInput.value;

  // 1. Get challenge from server
  const initResponse = await fetch(`${SERVER_URL}/init-auth?email=${email}`, {
    credentials: "include",
  });
  const options = await initResponse.json();
  if (!initResponse.ok) {
    showModalText(options.error);
  }

  // 2. Get passkey
  const authJSON = await startAuthentication(options);

  console.log("when logged in with authenticator, we have response", authJSON);

  // 3. Verify passkey with DB
  const verifyResponse = await fetch(`${SERVER_URL}/verify-auth`, {
    credentials: "include",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(authJSON),
  });

  const verifyData = await verifyResponse.json();
  if (!verifyResponse.ok) {
    showModalText(verifyData.error);
  }
  if (verifyData.verified) {
    showModalText(`Successfully logged in ${email}`);
  } else {
    showModalText(`Failed to log in`);
  }
}

async function createwallet() {
  const email = emailInput.value;

  //getting user information
  let initResponse = await fetch(
    `${SERVER_URL}/initCreateWallet?email=${email}`,
    {
      credentials: "include",
    }
  );

  if (!initResponse.ok) {
    showModalText(options.error);
  }
  const options = await initResponse.json();
  const authJSON = await startAuthentication(options);

  console.log("authJSON", authJSON);

  const sgxResponse = await fetch(`${SERVER_URL}/createWallet`, {
    credentials: "include",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(authJSON),
  });

  const sgxData = await sgxResponse.json();
  console.log("sgxData", sgxData);

  // showModalText(`Sgx Data ${JSON.stringify(sgxData.sgxData.data)}`);
  showJSON(sgxData.sgxData.data);
}

async function enableDelegate() {
  const email = emailInput.value;

  const initResponse = await fetch(
    `${SERVER_URL}/initCreateTransaction?email=${email}`,
    {
      credentials: "include",
    }
  );
  const options = await initResponse.json();
  if (!initResponse.ok) {
    showModalText(options.error);
  }
  const authJSON = await startAuthentication(options);
  console.log("authJSON", authJSON);

  const sgxResponse = await fetch(`${SERVER_URL}/enableDelegate`, {
    credentials: "include",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(authJSON),
  });

  if (sgxResponse.success) {
    showModalText(`Transaction hash: ${sgxResponse.hash}`);
  }

}

async function eipTx() {
  const email = emailInput.value;

  const initResponse = await fetch(
    `${SERVER_URL}/initCreateTransaction?email=${email}`,
    {
      credentials: "include",
    }
  );
  const options = await initResponse.json();
  if (!initResponse.ok) {
    showModalText(options.error);
  }
  const authJSON = await startAuthentication(options);
  console.log("authJSON", authJSON);

  const sgxResponse = await fetch(`${SERVER_URL}/eip7702transaction`, {
    credentials: "include",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(authJSON),
  });

  if (sgxResponse.success) {
    showModalText(`Transaction hash: ${sgxResponse.hash}`);
  }

}

async function selfcall() {
  const email = emailInput.value;

  const initResponse = await fetch(
    `${SERVER_URL}/initCreateTransaction?email=${email}`,
    {
      credentials: "include",
    }
  );
  const options = await initResponse.json();
  if (!initResponse.ok) {
    showModalText(options.error);
  }
  const authJSON = await startAuthentication(options);
  console.log("authJSON", authJSON);

  const sgxResponse = await fetch(`${SERVER_URL}/selfcall`, {
    credentials: "include",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(authJSON),
  });

  if (sgxResponse.success) {
    showModalText(`Transaction hash: ${sgxResponse.hash}`);
  }
}

async function sendTransaction() {
  const email = emailInput.value;

  const initResponse = await fetch(
    `${SERVER_URL}/initCreateTransaction?email=${email}`,
    {
      credentials: "include",
    }
  );
  const options = await initResponse.json();
  if (!initResponse.ok) {
    showModalText(options.error);
  }
  const authJSON = await startAuthentication(options);
  console.log("authJSON", authJSON);

  const sgxResponse = await fetch(`${SERVER_URL}/createTransaction`, {
    credentials: "include",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(authJSON),
  });

  if (sgxResponse.success) {
    showModalText(`Transaction hash: ${sgxResponse.hash}`);
  }
}

function showModalText(text) {
  modal.querySelector("[data-content]").innerText = text;
  modal.showModal();
}

function showJSON(data) {
  const output = document.querySelector("[data-output]");
  output.textContent =
    typeof data === "string" ? data : JSON.stringify(data, null, 2);
}
