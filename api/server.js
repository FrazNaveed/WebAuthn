const { webcrypto } = require("crypto");
const axios = require("axios");
const { keccak256, toBuffer, BN, bufferToHex } = require("ethereumjs-util");
const secp256k1 = require("secp256k1");
const rlp = require("rlp");

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
      "https://eth.llamarpc.com";

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
  value: toBuffer(new BN("1200000000000000")),
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
