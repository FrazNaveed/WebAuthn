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
    return res.json({ sgxData: {data: user.wallet} });
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

      return res.json({ sgxData: {data: sgxData.data} });
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

    res.status(200).json({delegate: rawDelegateHex});

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

    res.status(200).json({delegate: rawDelegateHex});

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
  if (value === 0 || value === '0' || value === '0x0') {
    return Buffer.alloc(0);
  }
  
  if (typeof value === 'string' && value.startsWith('0x')) {
    return Buffer.from(value.slice(2), 'hex');
  }
  
  if (typeof value === 'number') {
    const hex = value.toString(16);
    return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
  }
  
  return Buffer.from(value);
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
  const authInfo = JSON.parse(req.cookies.authInfo);
  if (!authInfo) {
    return res.status(400).json({ error: "Authentication info not found" });
  }

  const user = getUserById(authInfo.userId);
  if (!user || !user.wallet || user.passKey.id !== req.body.id) {
    return res.status(400).json({ error: "Invalid user or wallet not found" });
  }

  try {
    const chainId = req.body.chainId || 1; // Default to Ethereum Mainnet
    const ALCHEMY_URL = "https://mainnet.infura.io/v3/00904e37a5644a96be0e7ce44f71ba0f";

    // Get user's Ethereum address from wallet
    const fromAddress = "0x" + user.wallet.ethereumAddress;
    
    // EIP-7702 specific parameters
    const delegationAddress = "0xaCacbf32631D9C3FFb1874E48359fbC532A3ce56";
    const toAddress = req.body.to || "0xAc2F5e28558588a02FD1839Bb7022Df45494061E";
    const value = req.body.value || "0x0"; // Default to 0 value
    const calldata = req.body.calldata || "0x"; // Default to empty calldata
    const accessList = req.body.accessList || []; // Default to empty access list array

    if (!delegationAddress) {
      return res.status(400).json({ error: "delegationAddress is required for EIP-7702 transactions" });
    }

    // Get current nonce and gas parameters
    const [nonceResponse, gasPriceResponse, maxFeeResponse] = await Promise.all([
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
      // For EIP-1559 transactions, we need to get base fee
      axios.post(ALCHEMY_URL, {
        jsonrpc: "2.0",
        method: "eth_getBlockByNumber",
        params: ["latest", false],
        id: 3,
      })
    ]);

    const currentNonce = parseInt(nonceResponse.data.result, 16);
    const gasPrice = parseInt(gasPriceResponse.data.result, 16);
    const baseFee = parseInt(maxFeeResponse.data.result.baseFeePerGas, 16);
    
    // Calculate EIP-1559 gas parameters
    const maxPriorityFeePerGas = Math.floor(gasPrice * 0.5); // 10% tip
    const maxFeePerGas = Math.floor(baseFee * 2 + maxPriorityFeePerGas); // 2x base fee + tip
    const gasLimit = req.body.gasLimit || 100000; // Higher limit for EIP-7702 transactions
    
    // Transaction nonce (can be different from current nonce for batching)
    const txNonce = req.body.nonce !== undefined ? parseInt(req.body.nonce, 16) : currentNonce;

    console.log("EIP-7702 Transaction Parameters:");
    console.log("- Chain ID:", chainId);
    console.log("- From:", fromAddress);
    console.log("- To:", toAddress);
    console.log("- Delegation Address:", delegationAddress);
    console.log("- Current Nonce:", currentNonce);
    console.log("- Transaction Nonce:", txNonce);
    console.log("- Max Priority Fee:", maxPriorityFeePerGas, "wei");
    console.log("- Max Fee:", maxFeePerGas, "wei");
    console.log("- Gas Limit:", gasLimit);

    // Convert all parameters to hex strings (removing 0x prefix for SGX service)
    // Ensure canonical representation (no leading zeros except for zero value)
    const toCanonicalHex = (value) => {
      if (value === 0 || value === '0' || value === '0x0' || value === '0x') {
        return '0x'; // Empty for zero values to avoid leading zeros
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

    // Convert access list to proper format
    const formatAccessList = (accessList) => {
      if (!accessList || accessList.length === 0) {
        return ""; // Empty string for empty access list - will be encoded as empty RLP list
      }
      
      // If access list has items, format them properly
      // Access list format: [[address, [storage_keys]], ...]
      const formatted = accessList.map(item => {
        return {
          address: item.address,
          storageKeys: item.storageKeys || []
        };
      });
      
      return JSON.stringify(formatted);
    };

    const removeHexPrefix = (hex) => {
      return hex.startsWith('0x') ? hex.slice(2) : hex;
    };

    // Prepare the message body for SGX service
    const messageBody = {
      clientDataJSON: req.body.response.clientDataJSON,
      authenticatorData: req.body.response.authenticatorData,
      signature: req.body.response.signature,
      "account-seal": user.wallet.accountSeal,
      "account-type": 0, // 0 for BTC/ETH, 1 for Solana
      
      // EIP-7702 specific fields (as hex strings with canonical encoding)
      chainId: toCanonicalHex(chainId),
      delegationAddress: toCanonicalHex(delegationAddress),
      nonce: toCanonicalHex(txNonce),
      currentNonce: toCanonicalHex(currentNonce),
      maxPriorityFeePerGas: toCanonicalHex(maxPriorityFeePerGas),
      maxFeePerGas: toCanonicalHex(maxFeePerGas),
      gasLimit: toCanonicalHex(gasLimit),
      sender: toCanonicalHex(fromAddress),
      value: toCanonicalHex(value), // This should be '0x' for zero value
      calldata: calldata === '0x' ? "" : calldata, // Empty string for empty calldata
      accessList: formatAccessList(accessList) // Properly formatted access list
    };

    console.log("Sending request to SGX service...");
    console.log("Message body:", JSON.stringify(messageBody, null, 2));

    // Call the SGX service
    const sgxResponse = await axios.post(
      "http://localhost:8080/eip7702txsign",
      messageBody,
      {
        headers: {
          "Content-Type": "application/json",
        },
        timeout: 10000, // 10 second timeout for EIP-7702 transactions
      }
    );

    if (!sgxResponse.data) {
      throw new Error("Empty response from SGX service");
    }

    console.log("SGX Response:", sgxResponse.data);

    // Extract the signed transaction from SGX response
    const signedTransaction = sgxResponse.data.signedTransaction;
    const accountType = sgxResponse.data["account-type"];

    if (!signedTransaction) {
      throw new Error("No signed transaction returned from SGX service");
    }

    // Add 0x prefix if not present
    const signedTxHex = signedTransaction.startsWith('0x') ? signedTransaction : '0x' + signedTransaction;

    console.log("Signed EIP-7702 transaction:", signedTxHex);

    // Broadcast the transaction to the network
    try {
      const { data } = await axios.post(ALCHEMY_URL, {
        jsonrpc: "2.0",
        method: "eth_sendRawTransaction",
        params: [signedTxHex],
        id: 4,
      });

      console.log("EIP-7702 Transaction broadcast response:", data);

      if (data.error) {
        throw new Error(`Transaction broadcast failed: ${data.error.message}`);
      }

      console.log("EIP-7702 Transaction hash:", data.result);
      
      return res.json({
        success: true,
        hash: data.result,
        signedTransaction: signedTxHex,
        accountType: accountType,
        transactionType: "EIP-7702",
        delegationAddress: delegationAddress
      });

    } catch (broadcastError) {
      console.error("Transaction broadcast failed:", broadcastError.response?.data || broadcastError.message);
      
      // Return the signed transaction even if broadcast fails
      // This allows the client to retry broadcasting or use a different RPC
      return res.json({
        success: false,
        error: "Transaction broadcast failed",
        signedTransaction: signedTxHex,
        accountType: accountType,
        transactionType: "EIP-7702",
        delegationAddress: delegationAddress,
        broadcastError: broadcastError.response?.data || broadcastError.message
      });
    }

  } catch (error) {
    console.error("EIP-7702 transaction error:", error.response?.data || error.message);
    
    // Provide more specific error messages
    let errorMessage = "EIP-7702 transaction failed";
    if (error.response?.data) {
      if (typeof error.response.data === 'string') {
        errorMessage = error.response.data;
      } else if (error.response.data.error) {
        errorMessage = error.response.data.error;
      }
    } else if (error.message) {
      errorMessage = error.message;
    }

    return res.status(500).json({
      success: false,
      error: errorMessage,
      transactionType: "EIP-7702"
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
    const toAddress = "0xAc2F5e28558588a02FD1839Bb7022Df45494061E";

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
  value: toBuffer(new BN("12000")),
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
