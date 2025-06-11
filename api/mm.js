// Install dependencies: npm install @noble/secp256k1 @noble/hashes
const secp = require('@noble/secp256k1');
const { keccak_256 } = require('@noble/hashes/sha3');

// Helper function to convert hex string to Uint8Array
function hexToBytes(hex) {
    if (hex.startsWith('0x')) hex = hex.slice(2);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

// Helper function to convert Uint8Array to hex string
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Debug function to show detailed recovery attempt
async function debugRecoveryAttempt(messageHash, r, s, expectedPubkey, recoveryId) {
    try {
        console.log(`\n--- Trying recovery ID ${recoveryId} ---`);
        
        const rBytes = typeof r === 'string' ? hexToBytes(r) : r;
        const sBytes = typeof s === 'string' ? hexToBytes(s) : s;
        const hashBytes = typeof messageHash === 'string' ? hexToBytes(messageHash) : messageHash;
        const expectedPubkeyBytes = typeof expectedPubkey === 'string' ? hexToBytes(expectedPubkey) : expectedPubkey;

        const signature = new secp.Signature(
            BigInt('0x' + bytesToHex(rBytes)),
            BigInt('0x' + bytesToHex(sBytes))
        );

        const recoveredPubkey = signature.recoverPublicKey(hashBytes, recoveryId);
        const recoveredPubkeyBytes = recoveredPubkey.toRawBytes(false); // uncompressed format
        
        console.log('Expected pubkey:', bytesToHex(expectedPubkeyBytes));
        console.log('Recovered pubkey:', bytesToHex(recoveredPubkeyBytes));
        
        const matches = bytesToHex(recoveredPubkeyBytes).toLowerCase() === bytesToHex(expectedPubkeyBytes).toLowerCase();
        console.log('Matches:', matches);
        
        return matches ? recoveryId : -1;
    } catch (error) {
        console.log(`Recovery ID ${recoveryId} failed:`, error.message);
        return -1;
    }
}

// Enhanced recovery ID computation with detailed debugging
async function computeRecoveryId(messageHash, r, s, expectedPubkey) {
    console.log('\n=== RECOVERY DEBUG INFO ===');
    console.log('Message hash:', typeof messageHash === 'string' ? messageHash : bytesToHex(messageHash));
    console.log('R:', typeof r === 'string' ? r : bytesToHex(r));
    console.log('S:', typeof s === 'string' ? s : bytesToHex(s));
    console.log('Expected pubkey:', typeof expectedPubkey === 'string' ? expectedPubkey : bytesToHex(expectedPubkey));

    // Try all recovery IDs with detailed logging
    for (let recoveryId = 0; recoveryId < 4; recoveryId++) {
        const result = await debugRecoveryAttempt(messageHash, r, s, expectedPubkey, recoveryId);
        if (result >= 0) {
            return result;
        }
    }
    
    return -1;
}

// Alternative approach: try different message hash formats
async function tryDifferentHashFormats(messageHex, r, s, expectedPubkey) {
    console.log('\n=== TRYING DIFFERENT HASH FORMATS ===');
    
    const messageBytes = hexToBytes(messageHex);
    
    // Format 1: Direct Keccak-256 of message
    const hash1 = keccak_256(messageBytes);
    console.log('\nTrying Format 1 - Direct Keccak-256:');
    console.log('Hash:', bytesToHex(hash1));
    let recoveryId = await computeRecoveryId(hash1, r, s, expectedPubkey);
    if (recoveryId >= 0) return { recoveryId, hashFormat: 'direct_keccak' };

    // Format 2: Ethereum personal message format
    const prefix = new TextEncoder().encode('\x19Ethereum Signed Message:\n' + messageBytes.length);
    const prefixedMessage = new Uint8Array(prefix.length + messageBytes.length);
    prefixedMessage.set(prefix, 0);
    prefixedMessage.set(messageBytes, prefix.length);
    const hash2 = keccak_256(prefixedMessage);
    console.log('\nTrying Format 2 - Ethereum personal message:');
    console.log('Hash:', bytesToHex(hash2));
    recoveryId = await computeRecoveryId(hash2, r, s, expectedPubkey);
    if (recoveryId >= 0) return { recoveryId, hashFormat: 'ethereum_personal' };

    // Format 3: Raw message bytes (no additional hashing)
    console.log('\nTrying Format 3 - Raw message as hash:');
    if (messageBytes.length === 32) {
        console.log('Hash:', bytesToHex(messageBytes));
        recoveryId = await computeRecoveryId(messageBytes, r, s, expectedPubkey);
        if (recoveryId >= 0) return { recoveryId, hashFormat: 'raw_message' };
    }

    // Format 4: Double SHA-256 (Bitcoin style)
    const crypto = require('crypto');
    const sha256_1 = crypto.createHash('sha256').update(messageBytes).digest();
    const hash4 = crypto.createHash('sha256').update(sha256_1).digest();
    console.log('\nTrying Format 4 - Double SHA-256:');
    console.log('Hash:', bytesToHex(hash4));
    recoveryId = await computeRecoveryId(hash4, r, s, expectedPubkey);
    if (recoveryId >= 0) return { recoveryId, hashFormat: 'double_sha256' };

    return { recoveryId: -1, hashFormat: 'none' };
}

// Check if S value needs to be normalized (canonical form)
function normalizeS(s) {
    const sBytes = typeof s === 'string' ? hexToBytes(s) : s;
    const sBigInt = BigInt('0x' + bytesToHex(sBytes));
    
    // secp256k1 curve order
    const curveOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
    const halfOrder = curveOrder / 2n;
    
    // If S > half order, use curveOrder - S
    if (sBigInt > halfOrder) {
        const normalizedS = curveOrder - sBigInt;
        const normalizedSBytes = new Uint8Array(32);
        const hex = normalizedS.toString(16).padStart(64, '0');
        for (let i = 0; i < 32; i++) {
            normalizedSBytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return normalizedSBytes;
    }
    
    return sBytes;
}

// Manual verification to understand what's happening
async function manualVerification(messageHex, r, s, expectedPubkeyHex) {
    console.log('Performing manual verification to understand the issue...');
    
    // Let's verify the signature components are valid
    const rBigInt = BigInt('0x' + bytesToHex(r));
    const sBigInt = BigInt('0x' + bytesToHex(s));
    const curveOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
    
    console.log('R valid (> 0 and < curve order):', rBigInt > 0n && rBigInt < curveOrder);
    console.log('S valid (> 0 and < curve order):', sBigInt > 0n && sBigInt < curveOrder);
    
    // FIXED: Try to validate the expected public key using the correct API
    try {
        const pubkeyBytes = hexToBytes(expectedPubkeyHex);
        
        // Check if it's a valid public key by trying to create a Point from it
        // Use the correct method for @noble/secp256k1
        const pubkeyHex = bytesToHex(pubkeyBytes);
        const point = secp.Point.fromHex(pubkeyHex);
        console.log('Expected public key is valid on secp256k1 curve');
        
        // Additional validation: check if it's on the curve
        console.log('Point is on curve:', point.hasEvenY() !== undefined); // This will work if point is valid
        
    } catch (error) {
        console.log('Expected public key validation failed:', error.message);
        
        // Let's also check the format
        const pubkeyBytes = hexToBytes(expectedPubkeyHex);
        console.log('Public key length:', pubkeyBytes.length);
        console.log('First byte (should be 0x04 for uncompressed):', pubkeyBytes[0].toString(16));
        
        // Try different interpretations
        if (pubkeyBytes.length === 65 && pubkeyBytes[0] === 0x04) {
            console.log('Format appears to be uncompressed (65 bytes, starts with 0x04)');
        } else if (pubkeyBytes.length === 33) {
            console.log('Format appears to be compressed (33 bytes)');
        } else {
            console.log('Unknown public key format');
        }
    }
    
    // Additional check: Let's see if the message and expected pubkey have suspicious similarities
    console.log('\n=== SUSPICIOUS PATTERN ANALYSIS ===');
    const messageBytes = hexToBytes(messageHex);
    const pubkeyBytes = hexToBytes(expectedPubkeyHex);
    
    if (messageBytes.length === 32 && pubkeyBytes.length >= 32) {
        const messageStart = bytesToHex(messageBytes.slice(0, 32));
        const pubkeyStart = bytesToHex(pubkeyBytes.slice(1, 33)); // Skip 0x04 prefix
        
        console.log('Message (32 bytes):', messageStart);
        console.log('Pubkey X coord (32 bytes):', pubkeyStart);
        console.log('Message matches pubkey X coordinate:', messageStart === pubkeyStart);
        
        if (messageStart === pubkeyStart) {
            console.log('⚠️  WARNING: Message appears to be the X coordinate of the public key!');
            console.log('This suggests the message might be incorrectly formatted or the wrong data.');
        }
    }
}

// Main function with comprehensive debugging
async function computeRecoveryIdFromSignature(messageHex, signatureHex, expectedPubkeyHex) {
    try {
        console.log('=== INPUT DATA ===');
        console.log('Message:', messageHex);
        console.log('Signature:', signatureHex);
        console.log('Expected pubkey:', expectedPubkeyHex);

        // Parse the signature
        const signatureBytes = hexToBytes(signatureHex);
        
        if (signatureBytes.length !== 65) {
            throw new Error('Invalid signature length: ' + signatureBytes.length);
        }
        
        const r = signatureBytes.slice(0, 32);
        const s = signatureBytes.slice(32, 64);
        const v = signatureBytes[64];
        
        console.log('\n=== SIGNATURE COMPONENTS ===');
        console.log('R:', bytesToHex(r));
        console.log('S:', bytesToHex(s));
        console.log('V (from enclave):', v);
        
        // Check if S needs normalization
        const normalizedS = normalizeS(s);
        const sNormalized = !Buffer.from(s).equals(Buffer.from(normalizedS));
        
        if (sNormalized) {
            console.log('\n=== S VALUE NORMALIZATION ===');
            console.log('Original S:', bytesToHex(s));
            console.log('Normalized S:', bytesToHex(normalizedS));
        }

        // Always perform manual verification first to understand the data
        console.log('\n=== MANUAL VERIFICATION ===');
        await manualVerification(messageHex, r, s, expectedPubkeyHex);

        // If v is 5, we need to compute the recovery ID
        if (v === 5) {
            console.log('\nComputing recovery ID...');
            
            // Try with original S first
            let result = await tryDifferentHashFormats(messageHex, r, s, expectedPubkeyHex);
            
            // If that fails and S was normalized, try with normalized S
            if (result.recoveryId < 0 && sNormalized) {
                console.log('\n=== TRYING WITH NORMALIZED S ===');
                result = await tryDifferentHashFormats(messageHex, r, normalizedS, expectedPubkeyHex);
            }
            
            if (result.recoveryId >= 0) {
                console.log('\n=== SUCCESS ===');
                console.log('Recovery ID found:', result.recoveryId);
                console.log('Hash format:', result.hashFormat);
                
                const ethereumV = result.recoveryId + 27;
                console.log('Ethereum v value:', ethereumV);
                
                // Return updated signature (use normalized S if that's what worked)
                const finalS = (result.recoveryId >= 0 && sNormalized) ? normalizedS : s;
                const updatedSignature = new Uint8Array(65);
                updatedSignature.set(r, 0);
                updatedSignature.set(finalS, 32);
                updatedSignature[64] = ethereumV;
                
                return {
                    signature: bytesToHex(updatedSignature),
                    recoveryId: result.recoveryId,
                    v: ethereumV,
                    r: bytesToHex(r),
                    s: bytesToHex(finalS),
                    hashFormat: result.hashFormat,
                    sNormalized: sNormalized
                };
            } else {
                console.log('\n=== FAILURE ===');
                console.log('Recovery ID not found with any hash format');
                
                return null;
            }
        } else {
            console.log('Recovery ID already computed:', v);
            const ethereumV = v >= 27 ? v : v + 27;
            return {
                signature: signatureHex,
                recoveryId: v >= 27 ? v - 27 : v,
                v: ethereumV,
                r: bytesToHex(r),
                s: bytesToHex(s),
                hashFormat: 'preset',
                sNormalized: false
            };
        }
    } catch (error) {
        console.error('Error in computeRecoveryIdFromSignature:', error);
        return null;
    }
}

// Example usage
async function main() {
    // Your actual data
    const messageHex = "267bf25b7f3bdb9032f0fec35c3dfb5bb993c7a4292abc539067ad6e2e6d1d6d";
    const signatureHex = "3b63bf9e72a63b5428539b6b3c1a791668ee459bc5bd9711456929721fd7599b5ec5728ffde75d4dcc8b65b7a56d726ef893d891061b1ae9d9ae8b30cacc28cf05";
    const expectedPubkeyHex = "0446a32adc3c96aa11c93d1f45f6c49f971075cfe2a54385189ec02928051703a703697c7d541f7cc7803a6a0df61f544ade444bf17311f90795e626238c3234c1";

    const result = await computeRecoveryIdFromSignature(messageHex, signatureHex, expectedPubkeyHex);
    
    if (result) {
        console.log('\n=== FINAL RESULT ===');
        console.log('Success! Recovery ID computed.');
        console.log('Final signature:', result.signature);
        console.log('Recovery ID:', result.recoveryId);
        console.log('Ethereum v value:', result.v);
    } else {
        console.log('\nFailed to compute recovery ID. Check the message data.');
        
        // Provide some debugging suggestions
        console.log('\n=== DEBUGGING SUGGESTIONS ===');
        console.log('1. Verify that the message is the actual data that was signed');
        console.log('2. Check if the message needs different preprocessing');
        console.log('3. Confirm the public key format and encoding');
        console.log('4. Verify the signature was generated correctly');
    }
}

// Run if called directly
if (require.main === module) {
    main().catch(console.error);
}

module.exports = {
    computeRecoveryIdFromSignature,
    computeRecoveryId,
    hexToBytes,
    bytesToHex
};