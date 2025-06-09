const { webcrypto } = require("crypto");
const axios = require("axios");

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
    // const nonceResponse  = await axios.post(
    //   "http://localhost:8080/generateUserNonce",
    //   {
    //     publicKey: passkey.publicKey,
    //     publicKeyAlgorithm: passkey.algorithm,
    //   },
    //   {
    //     headers: {
    //       "Content-Type": "application/json",
    //     },
    //   }
    // );

    // comment this out
    const nonceResponse = {
      data: {
        nonce: "aGVsbG8gYWJj",
      },
    };

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

  try {
    // const sgxData = await axios.post(
    //   "http://localhost:8080/createNewWallet",
    //   {
    //     response: req.body,
    //   },
    //   {
    //     headers: {
    //       "Content-Type": "application/json",
    //     },
    //   }
    // );

    const sgxData = {
      data: {
        "pub-key":
          "l1t2yzr5eZnR37HZW3mBFbHsUkhf-lftDkKDABz9KPq8LB8dMAmegRggbTRTqSZD7fMkkl6Oi5VWBzKer6jQMgA",
        "account-seall":
          "BAACAAAAAABIIPM3auay8gNNO3pLSKd4CwAAAAAAAP8AAAAAAAAAADUqtNbuHs377HRNvQH6iZDUE0KlYHZfDb2bG87TS2rjAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAGyHAo5O_axJzdkCPgr7KfWnfY1x-Cl6YpeLB4Asl-ua1wEauy9I4C3mS--QMOXR9Z-G3GiJyKCF_5pHHDMzikO8TUMFKZ2y4xKLGhxy_Cx",
        "account-address": "34edeca6086a4b2ca31e10737c13db6369b01ff3",
      },
    };

    if (sgxData) {
      // updateUserCounter(user.id, verification.authenticationInfo.newCounter);
      res.clearCookie("authInfo"); // Clean up

      return res.json({ sgxData });
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

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
