const { webcrypto } = require("crypto");
const axios = require("axios");
const { keccak256, BN, bufferToHex } = require("ethereumjs-util"); // toBuffer
const secp256k1 = require("secp256k1");
const rlp = require("rlp");

console.log(toBuffer(rlp.encode("hello world")).toString("hex"))

console.log(toBuffer(rlp.encode([])).toString("hex"))

globalThis.crypto = webcrypto;
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const {
  getUserByEmail,
  createUser,
  updateUserCounter,
  getUserById,
  updateUserWallet,
  addUserDelegate,
} = require("./db");

const app = express();
app.use(express.json());
app.use(cookieParser());

const CLIENT_URL = "http://localhost:5173";
const RP_ID = "localhost";

// const CLIENT_URL = "https://206f-182-189-127-143.ngrok-free.app";
// const RP_ID = "206f-182-189-127-143.ngrok-free.app";

app.use(cors({ origin: CLIENT_URL, credentials: true }));

// Step 1: Initialize WebAuthn registration flow
app.get("/init-register", async (req, res) => {
  const email = req.query.email;

  // Step 1.1: Validate that email is present
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  // Step 1.2: Ensure the email isn't already registered
  if (getUserByEmail(email) != null) {
    return res.status(400).json({ error: "User already exists" });
  }

  // Step 1.3: Generate credential creation options using the FIDO2/WebAuthn spec
  const options = await generateRegistrationOptions({
    rpID: RP_ID, // Relying party ID (must match the domain)
    rpName: "My Web App", // Human-readable name of the RP
    userName: email, // Used for display name / user handle
    authenticatorSelection: {
      authenticatorAttachment: "platform", // Prefer platform authenticators (e.g., Touch ID, Face ID)
      residentKey: "required", // Credential must be stored on the device
      userVerification: "preferred", // Biometric/PIN preferred
    },
  });

  // Step 1.4: Store necessary state in secure cookie (challenge & userId)
  res.cookie(
    "regInfo",
    JSON.stringify({
      userId: options.user.id, // Generated user ID
      email,
      challenge: options.challenge, // Random challenge for client to sign
    }),
    {
      httpOnly: true, // Prevents JavaScript access
      maxAge: 60000, // Valid for 60 seconds
      secure: true, // HTTPS only
    }
  );

  // Step 1.5: Send options back to browser, to be used with `navigator.credentials.create()`
  res.json(options);
});

// Step 2: Complete registration - verify client's response
app.post("/verify-register", async (req, res) => {
  // Step 2.1: Retrieve challenge and metadata from cookie
  const regInfo = JSON.parse(req.cookies.regInfo);
  if (!regInfo) {
    return res.status(400).json({ error: "Registration info not found" });
  }

  // Step 2.2: Verify the registration response from the client
  const verification = await verifyRegistrationResponse({
    response: req.body, // This includes client data JSON, attestation object, etc.
    expectedChallenge: regInfo.challenge, // Must match what was sent earlier
    expectedOrigin: CLIENT_URL, // Must match frontend origin (e.g., https://example.com)
    expectedRPID: RP_ID, // Domain name (e.g., example.com)
    requireUserVerification: false, // Set to true to force biometrics
  });

  // Step 2.3: If verified, store credential in your DB
  if (verification.verified) {
    createUser(regInfo.userId, regInfo.email, {
      id: verification.registrationInfo.credentialID, // Unique identifier for the credential
      publicKey: req.body.response.publicKey, // For future signature verification
      publicKeyAlgorithm: req.body.response.publicKeyAlgorithm,
      counter: verification.registrationInfo.counter, // Used to detect cloned authenticators
      deviceType: verification.registrationInfo.credentialDeviceType, // 'singleDevice' or 'multiDevice'
      backedUp: verification.registrationInfo.credentialBackedUp, // Whether it's synced/backed-up
      transport: req.body.response.transports, // e.g., ["internal", "usb", "ble"]
    });

    // Step 2.4: Cleanup and respond
    res.clearCookie("regInfo"); // Done with this cookie
    return res.json({ verified: verification.verified });
  } else {
    return res.status(400).json({
      verified: false,
      error: "Verification failed",
    });
  }
});

// Step 3: Initialize login - send challenge to client
app.get("/init-auth", async (req, res) => {
  const email = req.query.email;

  // Step 3.1: Validate input
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  // Step 3.2: Load user by email from your DB
  const user = getUserByEmail(email);
  if (user == null) {
    return res.status(400).json({ error: "No user for this email" });
  }

  // Step 3.3: Create authentication challenge options
  const options = await generateAuthenticationOptions({
    rpID: RP_ID, // Domain
    allowCredentials: [
      {
        id: user.passKey.id, // Use the credential previously registered
        type: "public-key",
        transports: user.passKey.transports, // How the credential is accessed (USB, BLE, internal, etc.)
      },
    ],
    userVerification: "preferred", // "required" enforces biometrics
  });

  // Step 3.4: Store challenge in a secure cookie
  res.cookie(
    "authInfo",
    JSON.stringify({
      userId: user.id,
      challenge: options.challenge,
    }),
    {
      httpOnly: true,
      maxAge: 60000,
      secure: true,
    }
  );

  // Step 3.5: Send options to frontend for use with `navigator.credentials.get()`
  res.json(options);
});

// Step 4: Verify authentication response from client
app.post("/verify-auth", async (req, res) => {
  // Step 4.1: Retrieve challenge and user info from cookie
  const authInfo = JSON.parse(req.cookies.authInfo);
  if (!authInfo) {
    return res.status(400).json({ error: "Authentication info not found" });
  }

  // Step 4.2: Lookup user and validate credential ID
  const user = getUserById(authInfo.userId);
  if (user == null || user.passKey.id !== req.body.id) {
    return res.status(400).json({ error: "Invalid user" });
  }

  try {
    // Step 4.3: Verify authentication response
    const verification = await verifyAuthenticationResponse({
      response: req.body, // Client response (includes authenticator data, signature, etc.)
      expectedChallenge: authInfo.challenge,
      expectedOrigin: CLIENT_URL,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: user.passKey.id,
        credentialPublicKey: user.passKey.publicKey,
        counter: user.passKey.counter,
        transports: user.passKey.transports,
      },
      requireUserVerification: false, // Can be true if enforcing biometrics
    });

    // Step 4.4: Update counter (protects against cloned devices)
    if (verification.verified) {
      updateUserCounter(user.id, verification.authenticationInfo.newCounter);
      res.clearCookie("authInfo"); // Clean up
      return res.json({ verified: verification.verified });
    } else {
      return res.status(400).json({
        verified: false,
        error: "Verification failed",
      });
    }
  } catch (error) {
    console.error("Authentication error:", error);
    return res.status(500).json({ error: error.message });
  }
});

// create wallet route to get user's public key by email
app.get("/initCreateWallet", async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const user = await getUserByEmail(email);
  console.log("user", user);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const passkey = user.passKey;
  if (!passkey || !passkey.publicKey) {
    return res
      .status(404)
      .json({ error: "No passkey registered for this user" });
  }

  try {
    const nonceResponse = await axios.post(
      "http://localhost:8080/generateUserNonce",
      {
        publicKey: passkey.publicKey,
        publicKeyAlgorithm: passkey.publicKeyAlgorithm,
      },
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    // comment this out
    // const nonceResponse = {
    //   data: {
    //     nonce: "aGVsbG8gYWJj",
    //   },
    // };

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: [
        {
          id: user.passKey.id,
          type: "public-key",
          transports: user.passKey.transports,
        },
      ],
      userVerification: "preferred",
    });

    options.challenge = nonceResponse.data.nonce;

    res.cookie(
      "authInfo",
      JSON.stringify({
        userId: user.id,
        challenge: options.challenge,
      }),
      {
        httpOnly: true,
        maxAge: 60000,
        secure: true,
      }
    );

    res.json(options);
  } catch (error) {
    console.error("Error generating nonce:", error);
    return res.status(500).json({
      error: "Failed to generate nonce",
      details: error.response?.data || error.message,
    });
  }
});

app.post("/createWallet", async (req, res) => {
  const authInfo = JSON.parse(req.cookies.authInfo);
  if (!authInfo) {
    return res.status(400).json({ error: "Authentication info not found" });
  }

  const user = getUserById(authInfo.userId);
  if (user == null || user.passKey.id !== req.body.id) {
    return res.status(400).json({ error: "Invalid user" });
  }

  if (user.wallet) {
    return res.json({ sgxData: { data: user.wallet } });
  }

  const sgxPayload = {
    clientDataJSON: req.body.response.clientDataJSON,
    authenticatorData: req.body.response.authenticatorData,
    signature: req.body.response.signature,
  };

  try {
    const sgxData = await axios.post(
      "http://localhost:8080/createNewWallet",
      sgxPayload,
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    // const sgxData = {
    //   data: {
    //     "btc-eth-pubkey":
    //       "bybcqOsPr-TIXW_CQaoUW9vMRku2Vb_BhYl1flqOQgAFUjSi5MB3ztN_4lo9cuW7VPUWsM2WvLgtL0XXPrBsxAA",
    //     "account-seal":
    //       "BAACAAAAAABIIPM3auay8gNNO3pLSKd4CwAAAAAAAP8AAAAAAAAAALAkBuTlmwbv3PqKG_LxU6qqqTLO_UoeF4lT-7JsOFtgAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAAAAAAAAAAAG8QBpcYM9X1KDQYddxkfoEGqjNsSOMuLLqmPG7woOrOIc32CyHzE6f2943ureOUyMfoo3iYkBlJrLnlPz_vJm-9kCSzrTmlGaNXmxXbt2bSj__L8McTpSizgQyn8ARdlJOFZqUdpfCER11FPWFxM1U",
    //     "ethereum-address": "9e468f66eba9ea254e2a390115cb706f7a652da3",
    //     "solana-address": "7hxr6vNucgsPX1CaegLSpbxheVKq8FhHYxyEFNpqBiBm",
    //     "btc-address": "1NWKzivw9hbe1KSesruoRRAa5JdyXpnpia",
    //   },
    // };

    if (sgxData) {
      // updateUserCounter(user.id, verification.authenticationInfo.newCounter);

      const updatedUser = updateUserWallet(user.id, {
        ethereumAddress: sgxData.data["ethereum-address"],
        solanaAddress: sgxData.data["solana-address"],
        btcAddress: sgxData.data["btc-address"],
        btcEthPubKey: sgxData.data["btc-eth-pubkey"],
        accountSeal: sgxData.data["account-seal"],
      });

      if (!updatedUser) {
        return res.status(500).json({ error: "Failed to update user wallet" });
      }

      res.clearCookie("authInfo"); // Clean up

      return res.json({ sgxData: { data: sgxData.data } });
    } else {
      return res.status(400).json({
        verified: false,
        error: "Verification failed",
      });
    }
  } catch (error) {
    console.error("Authentication error:", error);
    return res.status(500).json({ error: error.message });
  }
});

// create txn endpoints
app.get("/initCreateTransaction", async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const user = await getUserByEmail(email);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const passkey = user.passKey;
  if (!passkey || !passkey.publicKey) {
    return res
      .status(404)
      .json({ error: "No passkey registered for this user" });
  }

  try {
    const nonceResponse = await axios.post(
      "http://localhost:8080/generateUserNonce",
      {
        publicKey: passkey.publicKey,
        publicKeyAlgorithm: passkey.publicKeyAlgorithm,
      },
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    // comment this out
    // const nonceResponse = {
    //   data: {
    //     nonce: "aGVsbG8gYWJj",
    //   },
    // };

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: [
        {
          id: user.passKey.id,
          type: "public-key",
          transports: user.passKey.transports,
        },
      ],
      userVerification: "preferred",
    });

    options.challenge = nonceResponse.data.nonce;

    res.cookie(
      "authInfo",
      JSON.stringify({
        userId: user.id,
        challenge: options.challenge,
      }),
      {
        httpOnly: true,
        maxAge: 60000,
        secure: true,
      }
    );

    res.json(options);
  } catch (error) {
    console.error("Error generating nonce:", error);
    return res.status(500).json({
      error: "Failed to generate nonce",
      details: error.response?.data || error.message,
    });
  }
});








app.post("/enableDelegate3", async (req, res) => {
  const authInfo = JSON.parse(req.cookies.authInfo);
  if (!authInfo) {
    return res.status(400).json({ error: "Authentication info not found" });
  }

  const user = getUserById(authInfo.userId);
  if (!user || !user.wallet || user.passKey.id !== req.body.id) {
    return res.status(400).json({ error: "Invalid user or wallet not found" });
  }

  try {
    const chainId = 1; // Arbitrum Mainnet
    const ALCHEMY_URL =
      // "https://arb-mainnet.g.alchemy.com/v2/LoyiQqdGjjR-z88vsuA0WofB-5i2r2UD";
      "https://eth.llamarpc.com";
    // "http://localhost:8545";

    const fromAddress = "0x" + user.wallet.ethereumAddress;
    const toAddress = "0xd9103C35Ac62999d66C186Fdab369d9328e3f6cD";

    // The contract address you want to delegate to
    const delegateToAddress = "0x8E8e658E22B12ada97B402fF0b044D6A325013C7"; // LightAccount Implementation 2.0

    // Get nonce and gas price in parallel
    const [nonceResponse, gasPriceResponse] = await Promise.all([
      axios.post(ALCHEMY_URL, {
        jsonrpc: "2.0",
        method: "eth_getTransactionCount",
        params: [fromAddress, "latest"],
        id: 1,
      }),
      axios.post(ALCHEMY_URL, {
        jsonrpc: "2.0",
        method: "eth_gasPrice",
        params: [],
        id: 2,
      })
    ]);

    const nonce = parseInt(nonceResponse.data.result, 16);
    const gasPrice = parseInt(gasPriceResponse.data.result, 16);
    const adjustedGasPrice = Math.floor(gasPrice * 1.1);

    console.log("Current gas price:", gasPrice, "wei");
    console.log("Adjusted gas price:", adjustedGasPrice, "wei");

    // Step 1: Create the authorization for EIP-7702
    // This authorizes the EOA to use the code from delegateToAddress
    const authorizationData = {
      chainId: chainId,
      address: delegateToAddress.toLowerCase().replace('0x', ''), // Remove 0x prefix
      nonce: nonce, // Can be different from tx nonce
    };

    // Create the authorization message to sign
    // EIP-7702 authorization format: keccak256(abi.encode(MAGIC, chainId, address, nonce))
    const MAGIC = "0x05"; // EIP-7702 magic number

    // Pack the authorization data for signing
    const authMessage = Buffer.concat([
      Buffer.from(MAGIC.slice(2), 'hex'),
      toBuffer(authorizationData.chainId),
      Buffer.from(authorizationData.address, 'hex'),
      toBuffer(authorizationData.nonce)
    ]);

    const authHash = keccak256(authMessage);
    const authHashBase64Url = authHash
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    console.log("Authorization hash:", authHash.toString('hex'));

    // Sign the authorization with SGX
    const authMessageBody = {
      clientDataJSON: req.body.response.clientDataJSON,
      authenticatorData: req.body.response.authenticatorData,
      signature: req.body.response.signature,
      challengeId: 0,
      "account-seal": user.wallet.accountSeal,
      "account-type": 0,
      message: authHashBase64Url,
    };

    const authSgxResponse = await axios.post(
      "http://localhost:8080/signMessage",
      authMessageBody,
      {
        headers: { "Content-Type": "application/json" },
        timeout: 5000,
      }
    );

    if (!authSgxResponse.data) {
      throw new Error("Empty response from SGX service for authorization");
    }

    // Parse authorization signature
    const authSignature = authSgxResponse.data.signature;
    const authBase64Signature = authSignature.replace(/-/g, '+').replace(/_/g, '/');
    const authPaddedSignature = authBase64Signature + '='.repeat((4 - authBase64Signature.length % 4) % 4);
    const authSigBuffer = Buffer.from(authPaddedSignature, 'base64');

    const authR = authSigBuffer.subarray(0, 32);
    const authS = authSigBuffer.subarray(32, 64);
    const authRecoveryId = authSigBuffer[64];
    const authV = authRecoveryId + 35 + chainId * 2;

    console.log("Authorization signature parsed");

    // Step 2: Create the actual transaction
    const txData = req.body.txData || "0x"; // The actual transaction data

    const txParams = {
      nonce: nonce === 0 ? Buffer.alloc(0) : toBuffer(nonce),
      gasPrice: toBuffer(adjustedGasPrice),
      gasLimit: toBuffer(100000), // Higher gas limit for EIP-7702
      to: toBuffer(toAddress),
      value: toBuffer(new BN("10")),
      data: Buffer.from(txData.slice(2), 'hex'),
      // EIP-7702 specific: authorization list
      authorizationList: [{
        chainId: toBuffer(authorizationData.chainId),
        address: Buffer.from(authorizationData.address, 'hex'),
        nonce: toBuffer(authorizationData.nonce),
        v: toBuffer(authV),
        r: authR[0] === 0 ? authR.subarray(1) : authR,
        s: authS[0] === 0 ? authS.subarray(1) : authS,
      }]
    };


    // Encode authorization list
    const encodedAuthList = rlp.encode([
      [
        txParams.authorizationList[0].chainId,
        txParams.authorizationList[0].address,
        txParams.authorizationList[0].nonce,
        txParams.authorizationList[0].v,
        txParams.authorizationList[0].r,
        txParams.authorizationList[0].s,
      ]
    ]);

    const rawDelegateHex = "0x" + toBuffer(encodedAuthList).toString('hex');
    console.log("DELEGAT :", rawDelegateHex)

    res.status(200).json({ delegate: rawDelegateHex });

    try {
      addUserDelegate(user.id, rawDelegateHex)
    } catch (err) {
      console.log(err)
    }

  } catch (error) {
    console.error("EIP-7702 Transaction error:", error);
    return res.status(500).json({
      error: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined,
    });
  }
});






















app.post("/enableDelegate", async (req, res) => {
  const authInfo = JSON.parse(req.cookies.authInfo);
  if (!authInfo) {
    return res.status(400).json({ error: "Authentication info not found" });
  }

  const user = getUserById(authInfo.userId);
  if (!user || !user.wallet || user.passKey.id !== req.body.id) {
    return res.status(400).json({ error: "Invalid user or wallet not found" });
  }

  try {
    const chainId = 1; // Ethereum Mainnet
    const ALCHEMY_URL = "https://eth.llamarpc.com";

    const fromAddress = "0x" + user.wallet.ethereumAddress;

    // The contract address you want to delegate to
    const delegateToAddress = "0x8E8e658E22B12ada97B402fF0b044D6A325013C7";

    // Get nonce for the authorization
    const nonceResponse = await axios.post(ALCHEMY_URL, {
      jsonrpc: "2.0",
      method: "eth_getTransactionCount",
      params: [fromAddress, "latest"],
      id: 1,
    });

    const authNonce = parseInt(nonceResponse.data.result, 16);

    console.log("Authorization nonce:", authNonce);
    console.log("Delegate to address:", delegateToAddress);

    // Step 1: Create the authorization for EIP-7702
    const authorizationData = {
      chainId: chainId,
      address: delegateToAddress.toLowerCase().replace('0x', ''),
      nonce: authNonce,
    };

    // Create the EIP-7702 authorization message
    const MAGIC = "0x05";

    const authMessage = Buffer.concat([
      Buffer.from(MAGIC.slice(2), 'hex'),
      toBuffer(authorizationData.chainId),
      Buffer.from(authorizationData.address, 'hex'),
      toBuffer(authorizationData.nonce)
    ]);

    const authHash = keccak256(authMessage);
    const authHashBase64Url = authHash
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    console.log("Authorization hash:", authHash.toString('hex'));

    // Sign the authorization with SGX
    const authMessageBody = {
      clientDataJSON: req.body.response.clientDataJSON,
      authenticatorData: req.body.response.authenticatorData,
      signature: req.body.response.signature,
      challengeId: 0,
      "account-seal": user.wallet.accountSeal,
      "account-type": 0,
      message: authHashBase64Url,
    };

    const authSgxResponse = await axios.post(
      "http://localhost:8080/signMessage",
      authMessageBody,
      {
        headers: { "Content-Type": "application/json" },
        timeout: 5000,
      }
    );

    if (!authSgxResponse.data) {
      throw new Error("Empty response from SGX service for authorization");
    }

    // Parse authorization signature
    const authSignature = authSgxResponse.data.signature;
    const authBase64Signature = authSignature.replace(/-/g, '+').replace(/_/g, '/');
    const authPaddedSignature = authBase64Signature + '='.repeat((4 - authBase64Signature.length % 4) % 4);
    const authSigBuffer = Buffer.from(authPaddedSignature, 'base64');

    const authR = authSigBuffer.subarray(0, 32);
    const authS = authSigBuffer.subarray(32, 64);
    const authRecoveryId = authSigBuffer[64];

    const authV = authRecoveryId;

    console.log("Authorization signature parsed:");
    console.log("Recovery ID:", authRecoveryId);
    console.log("v:", authV);

    // Create proper EIP-7702 authorization list entry
    // Format: [chainId, address, nonce, v, r, s]
    const authorizationEntry = [
      toBuffer(authorizationData.chainId),
      toAddressBuffer(delegateToAddress),  // Use dedicated address converter
      toBuffer(authorizationData.nonce),
      toBuffer(authV),
      authR,
      authS
    ];

    // Use the exact buffer format required
    const encodedAuthList = rlp.encode([authorizationEntry]);
    const rawDelegateHex = "0x" + encodedAuthList.toString("hex");

    console.log("Encoded authorization list:", rawDelegateHex);

    res.status(200).json({ delegate: rawDelegateHex });

    try {
      addUserDelegate(user.id, rawDelegateHex);
    } catch (err) {
      console.log("Error saving delegate:", err);
    }

  } catch (error) {
    console.error("EIP-7702 Authorization error:", error);
    return res.status(500).json({
      error: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined,
    });
  }
});

















const { ethers } = require('ethers');
const { Console } = require("console");

// Helper function to create canonical buffers (no leading zeros)
// function toBuffer(value) {
//   if (value === 0 || value === '0' || value === '0x0') {
//     return Buffer.alloc(0); // Empty buffer for zero values
//   }

//   if (typeof value === 'string' && value.startsWith('0x')) {
//     value = value.slice(2);
//   }

//   if (typeof value === 'string') {
//     // Remove leading zeros but keep at least one digit
//     value = value.replace(/^0+/, '') || '0';
//     // Ensure even length for hex
//     if (value.length % 2 !== 0) {
//       value = '0' + value;
//     }
//     return Buffer.from(value, 'hex');
//   }

//   if (typeof value === 'number') {
//     if (value === 0) return Buffer.alloc(0);
//     return Buffer.from(value.toString(16).padStart(2, '0'), 'hex');
//   }

//   return Buffer.from(value);
// }

function toBuffer(value) {
  if (value === null || value === undefined) {
    return Buffer.alloc(0);
  }

  if (Buffer.isBuffer(value)) {
    return value;
  }

  if (typeof value === 'string') {
    if (value.startsWith('0x')) {
      const hex = value.slice(2);
      if (hex.length === 0) return Buffer.alloc(0);
      // Remove leading zeros for canonical encoding
      const cleanHex = hex.replace(/^0+/, '') || '0';
      return Buffer.from(cleanHex.length % 2 ? '0' + cleanHex : cleanHex, 'hex');
    }
    return Buffer.from(value);
  }

  if (typeof value === 'number') {
    if (value === 0) return Buffer.alloc(0);
    return Buffer.from(value.toString(16).padStart(value.toString(16).length % 2 ? value.toString(16).length + 1 : value.toString(16).length, '0'), 'hex');
  }

  if (BN.isBN(value)) {
    if (value.isZero()) return Buffer.alloc(0);
    return Buffer.from(value.toString(16, 'hex'), 'hex');
  }

  console.log(Buffer.from(value).toString("hex"))
  return Buffer.from(value).toString("hex");
  throw new Error(`Cannot convert ${typeof value} to buffer`);
}

// Dedicated address converter
function toAddressBuffer(address) {
  const cleanAddress = address.toLowerCase().replace('0x', '');
  if (cleanAddress.length !== 40) {
    throw new Error(`Invalid address: ${address}`);
  }
  return Buffer.from(cleanAddress, 'hex');
}
// Helper for bigint to buffer
function bigIntToBuffer(value) {
  return toBuffer(BigInt(value));
}


// Helper function specifically for addresses
// function toAddressBuffer(address) {
//   if (!address) return Buffer.alloc(0);

//   // Remove 0x prefix if present
//   const cleanAddress = address.toLowerCase().replace('0x', '');

//   // Validate address length (should be 40 hex characters = 20 bytes)
//   if (cleanAddress.length !== 40) {
//     throw new Error(`Invalid address length: ${cleanAddress.length}, expected 40 hex characters`);
//   }

//   return Buffer.from(cleanAddress, 'hex');
// }

// // Helper function specifically for addresses
// function toAddressBuffer(address) {
//   if (!address) return Buffer.alloc(0);

//   // Remove 0x prefix if present
//   const cleanAddress = address.toLowerCase().replace('0x', '');

//   // Validate address length (should be 40 hex characters = 20 bytes)
//   if (cleanAddress.length !== 40) {
//     throw new Error(`Invalid address length: ${cleanAddress.length}, expected 40 hex characters`);
//   }

//   return Buffer.from(cleanAddress, 'hex');
// }

app.post("/eip7702transaction", async (req, res) => {
  // Helper function to convert values to canonical hex format
  const toCanonicalHex = (value) => {
    if (value === 0 || value === '0' || value === '0x0' || value === '0x') {
      return '0x';
    }

    let hex;
    if (typeof value === 'string' && value.startsWith('0x')) {
      hex = value.slice(2);
    } else if (typeof value === 'number') {
      hex = value.toString(16);
    } else {
      hex = value.toString();
    }

    // Remove leading zeros but keep at least one digit
    hex = hex.replace(/^0+/, '') || '0';
    return '0x' + hex;
  };

  // Fixed helper function to ensure proper 32-byte signature components
  const toFixed32ByteHex = (buffer) => {
    const hex = buffer.toString("hex");
    // Pad to 64 characters (32 bytes) if needed
    const paddedHex = hex.padStart(64, '0');
    return '0x' + paddedHex;
  };

  // Helper function to estimate gas limit
  const estimateGasLimit = async (provider, txData, authorizationData, calldata, fromAddress) => {
    try {
      // Implementation would go here - placeholder for now
      return 1000000; // Default gas limit
    } catch (error) {
      console.error('Gas estimation failed:', error);
      return 1000000; // Fallback gas limit
    }
  };

  // Helper function to get balance with retry logic
  const getBalanceWithRetry = async (provider, address, maxRetries = 3) => {
    for (let i = 0; i < maxRetries; i++) {
      try {
        const balance = await provider.getBalance(address);
        console.log(`Balance check attempt ${i + 1}: ${ethers.formatEther(balance)} ETH`);
        return balance;
      } catch (error) {
        console.error(`Balance check attempt ${i + 1} failed:`, error.message);
        if (i === maxRetries - 1) throw error;
        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second
      }
    }
  };

  try {
    // Validate authentication
    const authInfo = JSON.parse(req.cookies.authInfo);
    if (!authInfo) {
      return res.status(400).json({ error: "Authentication info not found" });
    }

    const user = getUserById(authInfo.userId);
    if (!user || !user.wallet || user.passKey.id !== req.body.id) {
      return res.status(400).json({ error: "Invalid user or wallet not found" });
    }

    // Configuration
    const chainId = req.body.chainId || 1;
    const ALCHEMY_URL = "https://mainnet.infura.io/v3/00904e37a5644a96be0e7ce44f71ba0f";
    const fromAddress = "0x" + user.wallet.ethereumAddress;
    const delegationAddress = "0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9";

    if (!delegationAddress) {
      return res.status(400).json({ error: "delegationAddress is required for EIP-7702 transactions" });
    }

    console.log('From address:', fromAddress);

    // Setup provider first
    const provider = new ethers.JsonRpcProvider(ALCHEMY_URL, {
      chainId: 1,
      name: 'mainnet'
    });

    // Fetch blockchain data in parallel
    const [nonceResponse, gasPriceResponse, blockResponse] = await Promise.all([
      axios.post(ALCHEMY_URL, {
        jsonrpc: "2.0",
        method: "eth_getTransactionCount",
        params: [fromAddress, "latest"],
        id: 1,
      }),
      axios.post(ALCHEMY_URL, {
        jsonrpc: "2.0",
        method: "eth_gasPrice",
        params: [],
        id: 2,
      }),
      axios.post(ALCHEMY_URL, {
        jsonrpc: "2.0",
        method: "eth_getBlockByNumber",
        params: ["latest", false],
        id: 3,
      })
    ]);

    const currentNonce = parseInt(nonceResponse.data.result, 16);
    const gasPrice = parseInt(gasPriceResponse.data.result, 16);
    const baseFee = parseInt(blockResponse.data.result.baseFeePerGas, 16);

    console.log('Network state:', {
      nonce: currentNonce,
      gasPrice: ethers.formatUnits(gasPrice, 'gwei') + ' gwei',
      baseFee: ethers.formatUnits(baseFee, 'gwei') + ' gwei'
    });

    // Prepare contract interaction
    const batchInterface = new ethers.Interface([
      "function execute(address,uint256,bytes)"
    ]);

    const calls = [{
      data: "0x",
      to: "0xAC93939D0292aE9A536e34944853bc8047461420",
      value: ethers.parseEther("0.00001")
    }];

    const calldata = batchInterface.encodeFunctionData("execute", [
      calls[0].to,
      calls[0].value,
      calls[0].data
    ]);

    // Step 1: Get authorization signature from SGX
    const authMessageBody = {
      clientDataJSON: req.body.response.clientDataJSON,
      authenticatorData: req.body.response.authenticatorData,
      signature: req.body.response.signature,
      "account-seal": user.wallet.accountSeal,
      "account-type": 0,
      chainId: toCanonicalHex(chainId),
      delegationAddress: toCanonicalHex(delegationAddress),
      nonce: toCanonicalHex(currentNonce + 1),
    };

    const sgxAuthResponse = await axios.post(
      "http://localhost:8080/eip7702txsign",
      authMessageBody,
      {
        headers: { "Content-Type": "application/json" },
        timeout: 10000,
      }
    );

    console.log('SGX auth response:', sgxAuthResponse.data);

    // Parse authorization data
    const [_chainId, _delegateToAddress, _nonce] = ethers.decodeRlp(
      ["0x", sgxAuthResponse.data.rlp_encoded_auth_list.slice(2)].join("")
    );

    // Process authorization signature with fixed padding
    const base64AuthSig = sgxAuthResponse.data.auth_list_signa
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    const paddedAuthSig = base64AuthSig + '='.repeat((4 - base64AuthSig.length % 4) % 4);
    const authSigBuffer = Buffer.from(paddedAuthSig, 'base64');

    if (authSigBuffer.length !== 65) {
      throw new Error(`Invalid authorization signature length: ${authSigBuffer.length}, expected 65`);
    }

    const authR = authSigBuffer.subarray(0, 32);
    const authS = authSigBuffer.subarray(32, 64);
    const authRecoveryId = authSigBuffer[64];

    // Use fixed 32-byte hex conversion to prevent missing digits
    const authRHex = toFixed32ByteHex(authR);
    const authSHex = toFixed32ByteHex(authS);

    console.log('Auth signature components:');
    console.log('- Recovery ID:', authRecoveryId);
    console.log('- r length:', authRHex.length, 'value:', authRHex);
    console.log('- s length:', authSHex.length, 'value:', authSHex);

    // Validate signature component lengths
    if (authRHex.length !== 66 || authSHex.length !== 66) { // 0x + 64 hex chars
      throw new Error(`Invalid signature component length: r=${authRHex.length}, s=${authSHex.length}, expected 66 each`);
    }

    const authorizationData = {
      chainId: _chainId,
      address: _delegateToAddress,
      nonce: _nonce,
      yParity: authRecoveryId === 0 ? '0x' : '0x01',
      r: authRHex,
      s: authSHex
    };

    // Get fee data and check balance with retry logic
    const feeData = await provider.getFeeData();
    const balance = await getBalanceWithRetry(provider, fromAddress);
    
    // Use more conservative gas settings
    const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas || ethers.parseUnits('2', 'gwei');
    const maxFeePerGas = feeData.maxFeePerGas || ethers.parseUnits('20', 'gwei');
    const gasLimit = 300000n; // Increased gas limit for EIP-7702 transactions
    
    console.log('Gas settings:');
    console.log('- Max Priority Fee:', ethers.formatUnits(maxPriorityFeePerGas, 'gwei'), 'gwei');
    console.log('- Max Fee:', ethers.formatUnits(maxFeePerGas, 'gwei'), 'gwei');
    console.log('- Gas Limit:', gasLimit.toString());
    
    // Check account balance and calculate costs
    const valueTransfer = ethers.parseEther("0.00001");
    const estimatedGasCost = gasLimit * maxFeePerGas;
    const totalCost = estimatedGasCost + valueTransfer;
    
    console.log('Cost breakdown:');
    console.log('- Account balance:', ethers.formatEther(balance), 'ETH');
    console.log('- Gas cost estimate:', ethers.formatEther(estimatedGasCost), 'ETH');
    console.log('- Value transfer:', ethers.formatEther(valueTransfer), 'ETH');
    console.log('- Total required:', ethers.formatEther(totalCost), 'ETH');
    
    if (balance === 0n) {
      return res.status(400).json({
        error: 'Insufficient funds',
        details: `Account ${fromAddress} has zero balance. Please fund the account before sending transactions.`,
        balance: '0 ETH'
      });
    }
    
    if (balance < totalCost) {
      return res.status(400).json({
        error: 'Insufficient funds',
        details: `Balance: ${ethers.formatEther(balance)} ETH, Required: ${ethers.formatEther(totalCost)} ETH`,
        balance: ethers.formatEther(balance) + ' ETH',
        required: ethers.formatEther(totalCost) + ' ETH',
        shortfall: ethers.formatEther(totalCost - balance) + ' ETH'
      });
    }

    // Build transaction data
    const txData = [
      authorizationData.chainId,
      ethers.toBeHex(currentNonce),
      ethers.toBeHex(maxPriorityFeePerGas),
      ethers.toBeHex(maxFeePerGas),
      ethers.toBeHex(gasLimit),
      fromAddress,
      ethers.toBeHex(valueTransfer),
      calldata,
      [], // Access list
      [[ // Authorization list
        authorizationData.chainId,
        authorizationData.address,
        authorizationData.nonce,
        authorizationData.yParity,
        authorizationData.r,
        authorizationData.s
      ]]
    ];

    console.log('Transaction data structure:', {
      chainId: authorizationData.chainId,
      nonce: ethers.toBeHex(currentNonce),
      maxPriorityFeePerGas: ethers.toBeHex(maxPriorityFeePerGas),
      maxFeePerGas: ethers.toBeHex(maxFeePerGas),
      gasLimit: ethers.toBeHex(gasLimit),
      to: fromAddress,
      value: ethers.toBeHex(valueTransfer),
      authListLength: txData[9].length
    });

    // Encode transaction for signing
    const encodedTxData = ethers.concat([
      '0x04', // EIP-7702 transaction type
      ethers.encodeRlp(txData)
    ]);

    console.log('Encoded transaction data length:', encodedTxData.length);
    const txDataHash = ethers.keccak256(encodedTxData);
    console.log('Transaction hash for signing:', txDataHash);

    // Step 2: Get transaction signature from SGX
    const msgHashBase64Url = txDataHash
      .slice(2) // Remove 0x prefix
      .match(/.{2}/g) // Split into byte pairs
      .map(byte => String.fromCharCode(parseInt(byte, 16))) // Convert to characters
      .join(''); // Join into string

    const msgHashBase64 = btoa(msgHashBase64Url) // Convert to base64
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const txSignMessageBody = {
      clientDataJSON: req.body.response.clientDataJSON,
      authenticatorData: req.body.response.authenticatorData,
      signature: req.body.response.signature,
      challengeId: 0,
      "account-seal": user.wallet.accountSeal,
      "account-type": 0,
      message: msgHashBase64,
    };

    const sgxTxResponse = await axios.post(
      "http://localhost:8080/signMessage",
      txSignMessageBody,
      {
        headers: { "Content-Type": "application/json" },
        timeout: 10000,
      }
    );

    if (!sgxTxResponse.data || !sgxTxResponse.data.signature) {
      throw new Error('Failed to get transaction signature from SGX');
    }

    // Process transaction signature with fixed padding
    const txSignature = sgxTxResponse.data.signature;
    const base64TxSig = txSignature.replace(/-/g, '+').replace(/_/g, '/');
    const paddedTxSig = base64TxSig + '='.repeat((4 - base64TxSig.length % 4) % 4);
    const txSigBuffer = Buffer.from(paddedTxSig, 'base64');

    if (txSigBuffer.length !== 65) {
      throw new Error(`Invalid transaction signature length: ${txSigBuffer.length}, expected 65`);
    }

    const txR = txSigBuffer.subarray(0, 32);
    const txS = txSigBuffer.subarray(32, 64);
    const txRecoveryId = txSigBuffer[64];

    // Use fixed 32-byte hex conversion
    const txRHex = toFixed32ByteHex(txR);
    const txSHex = toFixed32ByteHex(txS);

    console.log('TX signature components:');
    console.log('- Recovery ID:', txRecoveryId);
    console.log('- r length:', txRHex.length, 'value:', txRHex);
    console.log('- s length:', txSHex.length, 'value:', txSHex);

    // Validate signature component lengths
    if (txRHex.length !== 66 || txSHex.length !== 66) {
      throw new Error(`Invalid TX signature component length: r=${txRHex.length}, s=${txSHex.length}, expected 66 each`);
    }

    if (txRecoveryId > 1) {
      throw new Error(`Invalid recovery ID: ${txRecoveryId}`);
    }

    // Create final signed transaction
    const signedTx = ethers.hexlify(ethers.concat([
      '0x04',
      ethers.encodeRlp([
        ...txData,
        txRecoveryId === 0 ? '0x' : '0x01',
        txRHex,
        txSHex
      ])
    ]));

    // Final verification before sending
    console.log('Final transaction verification:');
    console.log('- From address:', fromAddress);
    console.log('- Transaction length:', signedTx.length, 'bytes');
    console.log('- Final balance check...');
    
    const finalBalance = await provider.getBalance(fromAddress);
    console.log('- Current balance:', ethers.formatEther(finalBalance), 'ETH');
    
    if (finalBalance < totalCost) {
      throw new Error(`Insufficient funds at final check: ${ethers.formatEther(finalBalance)} ETH < ${ethers.formatEther(totalCost)} ETH required`);
    }
    
    // Send transaction to network
    const txHash = await provider.send('eth_sendRawTransaction', [signedTx]);
    console.log('Transaction sent successfully:', txHash);

    return res.status(200).json({
      success: true,
      transactionHash: txHash,
      message: 'EIP-7702 transaction sent successfully',
      gasUsed: gasLimit.toString(),
      effectiveGasPrice: ethers.formatUnits(maxFeePerGas, 'gwei') + ' gwei'
    });

  } catch (error) {
    console.error('EIP-7702 transaction error:', error);
    
    // Provide more specific error handling
    let errorMessage = 'Failed to process EIP-7702 transaction';
    let errorDetails = error.message;
    
    if (error.code === 'INSUFFICIENT_FUNDS') {
      errorMessage = 'Insufficient funds for transaction';
      errorDetails = 'Account balance is insufficient to cover gas costs and value transfer';
    } else if (error.code === 'INVALID_ARGUMENT') {
      errorMessage = 'Invalid transaction data';
      errorDetails = 'Transaction encoding failed - check signature components';
    } else if (error.message.includes('nonce')) {
      errorMessage = 'Invalid transaction nonce';
      errorDetails = 'Transaction nonce conflict - try again';
    }
    
    return res.status(500).json({
      error: errorMessage,
      details: errorDetails,
      code: error.code || 'UNKNOWN_ERROR'
    });
  }
});

















app.post("/createTransaction", async (req, res) => {
  const authInfo = JSON.parse(req.cookies.authInfo);
  if (!authInfo) {
    return res.status(400).json({ error: "Authentication info not found" });
  }

  const user = getUserById(authInfo.userId);
  if (!user || !user.wallet || user.passKey.id !== req.body.id) {
    return res.status(400).json({ error: "Invalid user or wallet not found" });
  }

  try {
    const chainId = 1; // Arbitrum Mainnet
    const ALCHEMY_URL =
      // "https://arb-mainnet.g.alchemy.com/v2/LoyiQqdGjjR-z88vsuA0WofB-5i2r2UD";
      "https://mainnet.infura.io/v3/00904e37a5644a96be0e7ce44f71ba0f";
    // "http://localhost:8545";

    // Get user's Ethereum address from wallet
    const fromAddress = "0x" + user.wallet.ethereumAddress;
    const toAddress = "0xAC93939D0292aE9A536e34944853bc8047461420";

    // Get nonce and gas price in parallel
    const [nonceResponse, gasPriceResponse] = await Promise.all([
      axios.post(ALCHEMY_URL, {
        jsonrpc: "2.0",
        method: "eth_getTransactionCount",
        params: [fromAddress, "latest"],
        id: 1,
      }),
      axios.post(ALCHEMY_URL, {
        jsonrpc: "2.0",
        method: "eth_gasPrice",
        params: [],
        id: 2,
      })
    ]);

    const nonce = parseInt(nonceResponse.data.result, 16);
    const gasPrice = parseInt(gasPriceResponse.data.result, 16);

    // Use 110% of current gas price for faster confirmation
    const adjustedGasPrice = Math.floor(gasPrice * 1.1);

    console.log("Current gas price:", gasPrice, "wei");
    console.log("Adjusted gas price:", adjustedGasPrice, "wei");

    console.log("Current gas price:", gasPrice, "wei");
    console.log("Adjusted gas price:", adjustedGasPrice, "wei");

    // Prepare transaction
    const txParams = {
      nonce: nonce === 0 ? Buffer.alloc(0) : toBuffer(nonce),
      gasPrice: toBuffer(adjustedGasPrice),
      gasLimit: toBuffer(50000),
      to: toBuffer(toAddress),
      // value: toBuffer(new BN("1200000000000000")),
      value: toBuffer(new BN("120000000")),
      data: Buffer.alloc(0),
    };
    // RLP encode transaction
    const rawTx = [
      txParams.nonce,
      txParams.gasPrice,
      txParams.gasLimit,
      txParams.to,
      txParams.value,
      txParams.data,
      toBuffer(chainId),
      Buffer.alloc(0),
      Buffer.alloc(0),
    ];

    const rlpEncoded = rlp.encode(rawTx);
    const msgHash = keccak256(Buffer.from(rlpEncoded));

    const msgHashBase64Url = msgHash
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    // Prepare the message body with all required fields
    const messageBody = {
      clientDataJSON: req.body.response.clientDataJSON,
      authenticatorData: req.body.response.authenticatorData,
      signature: req.body.response.signature,
      challengeId: 0, // Fixed for now
      "account-seal": user.wallet.accountSeal, // From user's wallet
      "account-type": 0, // 0 for btc_eth, 1 for solana (hardcoded)
      message: msgHashBase64Url, // RLP encoded tx messageHash as array
    };

    const sgxResponse = await axios.post(
      "http://localhost:8080/signMessage",
      messageBody,
      {
        headers: {
          "Content-Type": "application/json",
        },
        timeout: 5000, // 5 second timeout
      }
    );

    if (!sgxResponse.data) {
      throw new Error("Empty response from SGX service");
    }


    console.log("HELLO ")
    console.log(sgxResponse)

    // Replace the signature parsing section with this:

    if (sgxResponse.data) {
      const signature = sgxResponse.data.signature;

      // Convert base64url to base64
      const base64Signature = signature.replace(/-/g, '+').replace(/_/g, '/');
      const paddedSignature = base64Signature + '='.repeat((4 - base64Signature.length % 4) % 4);
      const sigBuffer = Buffer.from(paddedSignature, 'base64');

      console.log("Signature buffer length:", sigBuffer.length);
      console.log("sigBuffer", sigBuffer);

      if (sigBuffer.length !== 65) {
        throw new Error(`Invalid signature length: ${sigBuffer.length}, expected 65`);
      }

      // Extract r, s, and recovery ID
      const r = sigBuffer.subarray(0, 32);
      const s = sigBuffer.subarray(32, 64);
      const recoveryId = sigBuffer[64];

      console.log("Recovery ID:", recoveryId);
      console.log("r:", "0x" + r.toString("hex"));
      console.log("s:", "0x" + s.toString("hex"));

      // Validate recovery ID (should be 0 or 1)
      if (recoveryId > 1) {
        throw new Error(`Invalid recovery ID: ${recoveryId}`);
      }

      // Calculate v for EIP-155 (Ethereum mainnet)
      // v = recovery_id + 35 + chain_id * 2
      const v = recoveryId + 35 + chainId * 2;
      console.log("Calculated v:", v);

      // Create canonical buffers for r and s (remove leading zeros if any)
      const rBuffer = r[0] === 0 ? r.subarray(1) : r;
      const sBuffer = s[0] === 0 ? s.subarray(1) : s;

      console.log("txParams.nonce", txParams.nonce);

      const signedTx = [
        txParams.nonce,
        txParams.gasPrice,
        txParams.gasLimit,
        txParams.to,
        txParams.value,
        txParams.data,
        toBuffer(v),
        rBuffer,
        sBuffer,
      ];

      const rawSignedTx = rlp.encode(signedTx);
      const rawTxHex = "0x" + Buffer.from(rawSignedTx).toString("hex");

      console.log("Raw transaction hex:", rawTxHex);

      try {
        const { data } = await axios.post(ALCHEMY_URL, {
          jsonrpc: "2.0",
          method: "eth_sendRawTransaction",
          params: [rawTxHex],
          id: 2,
        });
        console.log("Transaction response:", data);
        console.log("Transaction hash:", data.result);

        return res.json({
          success: true,
          hash: data.result,
        });
      } catch (error) {
        console.error("Transaction failed:", error.response?.data || error.message);
        return res.status(400).json({
          success: false,
          error: error.response?.data || error.message,
        });
      }
    }

    // if (sgxResponse.data) {

    //   const signature = sgxResponse.data.signature;

    //   // Convert base64url to base64 (replace URL-safe characters)
    //   const base64Signature = signature.replace(/-/g, '+').replace(/_/g, '/');

    //   // Add padding if needed
    //   const paddedSignature = base64Signature + '='.repeat((4 - base64Signature.length % 4) % 4);

    //   // Convert to buffer
    //   const sigBuffer = Buffer.from(paddedSignature, 'base64');

    //   console.log("Signature buffer length:", sigBuffer.length); // Should be 65 bytes
    //   console.log("sigBuffer", (sigBuffer))

    //   // 2. Extract r, s, and recovery ID from 65-byte signature
    //   const r = "0x" + sigBuffer.subarray(0, 32).toString("hex");
    //   const s = "0x" + sigBuffer.subarray(32, 64).toString("hex");
    //   const recid = sigBuffer[64]; // Last byte is recovery ID

    //   const v = toBuffer(recid + 35 + chainId * 2);

    //   console.log("txParams.nonce", txParams.nonce)
    //   const signedTx = [
    //     txParams.nonce,
    //     txParams.gasPrice,
    //     txParams.gasLimit,
    //     txParams.to,
    //     txParams.value,
    //     txParams.data,
    //     v,
    //     toBuffer(r),
    //     toBuffer(s),
    //   ];

    //   const rawSignedTx = rlp.encode(signedTx);
    //   const rawTxHex = "0x" + Buffer.from(rawSignedTx).toString("hex");

    //   try {
    //     const { data } = await axios.post(ALCHEMY_URL, {
    //       jsonrpc: "2.0",
    //       method: "eth_sendRawTransaction",
    //       params: [rawTxHex],
    //       id: 2,
    //     });
    //     console.log(data)
    //     console.log("Transaction hash:", data.result);
    //   } catch (error) {
    //     console.error(
    //       "Transaction failed:",
    //       error.response?.data || error.message
    //     );
    //   }

    //   res.clearCookie("authInfo");

    //   return res.json({
    //     success: true,
    //     // hash: data.result,
    //     hash: "0x", //TODO : COMMENT THIS OUT
    //   });
    // } else {
    //   return res.status(400).json({
    //     success: false,
    //     error: "Verification failed",
    //   });
    // }
  } catch (error) {
    console.error("Transaction error:", error);
    return res.status(500).json({
      error: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined,
    });
  }
});

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});




// async function estimateGasLimit(provider, authorizationData, calldata, fromAddress) {
//   try {
//     console.log('Estimating gas for EIP-7702 transaction...');
//     console.log('Target EOA:', fromAddress);
//     console.log('Authorization address:', authorizationData.address);
//     console.log('Calldata length:', calldata?.length || 0);

//     // For EIP-7702, we're calling an EOA that will temporarily act as a contract
//     // The EOA gets the code from the authorized contract address

//     let estimatedGas;

//     try {
//       // Method 1: Try to estimate against the authorized contract directly
//       // This simulates what the EOA will do when it has the delegated code
//       const contractEstimateRequest = {
//         from: fromAddress,
//         to: authorizationData.address, // The contract whose code will be delegated
//         value: '0x0',
//         data: calldata || '0x',
//       };

//       console.log('Estimating against authorized contract:', authorizationData.address);
//       estimatedGas = await provider.estimateGas(contractEstimateRequest);
//       console.log('Contract simulation gas:', estimatedGas.toString());

//       // Add EIP-7702 specific overhead
//       const eip7702Overhead = 16000n; // Authorization verification overhead
//       estimatedGas = estimatedGas + eip7702Overhead;
//       console.log('With EIP-7702 overhead:', estimatedGas.toString());

//     } catch (error) {
//       console.log('Contract simulation failed:', error.message);

//       // Method 2: Manual calculation for EIP-7702
//       console.log('Using manual EIP-7702 calculation...');
//       estimatedGas = calculateEIP7702GasEstimate(calldata);
//     }

//     // Add safety buffer (30% for EIP-7702 due to complexity)
//     const gasWithBuffer = (estimatedGas * 130n) / 100n;
//     console.log('Gas with 30% buffer:', gasWithBuffer.toString());

//     return gasWithBuffer;

//   } catch (error) {
//     console.error('EIP-7702 gas estimation error:', error);
//     // Return a reasonable default for EIP-7702 transactions
//     return 200000n;
//   }
// }

// function calculateEIP7702GasEstimate(calldata) {
//   console.log('Calculating EIP-7702 gas estimate...');

//   // Base transaction cost
//   let gasEstimate = 21000n; // Base transaction gas

//   // EIP-7702 specific costs
//   gasEstimate += 16000n; // Authorization verification
//   gasEstimate += 2300n;  // DELEGATECALL overhead

//   // Calldata cost
//   if (calldata && calldata !== '0x') {
//     const calldataBytes = ethers.getBytes(calldata);
//     for (const byte of calldataBytes) {
//       gasEstimate += byte === 0 ? 4n : 16n;
//     }
//   }

//   // Contract execution estimation (conservative)
//   // Since we can't simulate the actual contract call, use heuristics
//   const calldataLength = calldata ? (calldata.length - 2) / 2 : 0;

//   if (calldataLength > 4) {
//     // Looks like a function call
//     gasEstimate += 50000n; // Base contract execution

//     // Add more gas based on calldata complexity
//     if (calldataLength > 100) {
//       gasEstimate += 30000n; // Complex function call
//     }
//     if (calldataLength > 500) {
//       gasEstimate += 50000n; // Very complex function call
//     }
//   }

//   console.log('Manual EIP-7702 gas estimate:', gasEstimate.toString());
//   return gasEstimate;
// }

// function calculateManualGasEstimate(calldata) {
//   console.log('Calculating manual gas estimate...');

//   // Base transaction cost
//   let gasEstimate = 21000n; // Base transaction gas

//   // EIP-7702 authorization overhead
//   gasEstimate += 16000n; // Per authorization

//   // Calldata cost
//   if (calldata && calldata !== '0x') {
//     const calldataBytes = ethers.getBytes(calldata);
//     for (const byte of calldataBytes) {
//       gasEstimate += byte === 0 ? 4n : 16n; // 4 gas for zero bytes, 16 for non-zero
//     }
//   }

//   // Additional buffer for contract execution
//   gasEstimate += 50000n; // Conservative buffer for contract calls

//   console.log('Manual gas estimate:', gasEstimate.toString());
//   return gasEstimate;
// }
