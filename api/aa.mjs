import { rlp } from 'ethereumjs-util';
import { ethers } from 'ethers';

// EIP-7702 Account ABI (simplified for execute function)
const EIP7702_ABI = [
  'function execute(address target, uint256 value, bytes calldata data) external'
];

// Helper function to convert BigInt to proper format for RLP encoding
function toRlpFormat(value) {
  if (typeof value === 'bigint') {
    if (value === 0n) return '0x';
    let hex = value.toString(16);
    // Ensure even length
    if (hex.length % 2 !== 0) hex = '0' + hex;
    return '0x' + hex;
  }
  return value;
}

// Helper function to encode authorization list for RLP
function encodeAuthorizationList(authList) {
  return authList.map(auth => [
    toRlpFormat(auth.chainId),
    auth.address,
    toRlpFormat(auth.nonce),
    auth.v,  // Keep as-is, don't convert
    auth.r,
    auth.s
  ]);
}

async function createEIP7702ExecuteTx({
  provider,          // ethers provider
  sender,            // EOA address (sender)
  nonce,             // EOA current nonce
  maxPriorityFee,    // Tip (in wei)
  maxFee,            // Max fee per gas (in wei)
  gasLimit,          // Gas units
  target,            // Target contract for execution
  callValue,         // Value to send with execution (wei)
  callData,          // Data for target contract
  privateKey         // EOA private key
}) {
  // 1. Get EIP-7702 account contract address
  const accountAddress = '0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9';
  
  // Verify the contract exists
  const contractCode = await provider.getCode(accountAddress);
  if (contractCode === '0x') {
    throw new Error('EIP-7702 account code not found at address');
  }

  // 2. Get network info
  const chainId = (await provider.getNetwork()).chainId;
  const wallet = new ethers.Wallet(privateKey);

  // 3. Create authorization signature
  // EIP-7702 authorization message format: MAGIC || chain_id || address || nonce
  const authDomain = ethers.concat([
    '0x05',  // EIP-7702 magic
    ethers.zeroPadValue(ethers.toBeHex(chainId), 32),
    ethers.zeroPadValue(accountAddress, 20),
    ethers.zeroPadValue('0x00', 8)  // nonce = 0
  ]);
  
  const authHash = ethers.keccak256(authDomain);
  const authSignature = wallet.signingKey.sign(authHash);

  // 4. Build authorization list  
  const authorizationList = [{
    chainId: BigInt(chainId),
    address: accountAddress,
    nonce: 0n,
    v: authSignature.v,  // Keep as number
    r: authSignature.r,
    s: authSignature.s
  }];

  // 5. Encode the execute call
  const accountInterface = new ethers.Interface(EIP7702_ABI);
  const data = accountInterface.encodeFunctionData('execute', [
    target,
    callValue,
    callData
  ]);

  // 6. Prepare transaction fields
  const txFields = {
    chainId: BigInt(chainId),
    nonce: BigInt(nonce),
    maxPriorityFeePerGas: BigInt(maxPriorityFee),
    maxFeePerGas: BigInt(maxFee),
    gasLimit: BigInt(gasLimit),
    to: sender,  // Send to self (the EOA will be temporarily delegated)
    value: BigInt(0),  // Value handled in execute call
    data: data,
    accessList: [],
    authorizationList: authorizationList
  };

  // 7. Create unsigned transaction for signing
  const unsignedTxData = [
    toRlpFormat(txFields.chainId),
    toRlpFormat(txFields.nonce),
    toRlpFormat(txFields.maxPriorityFeePerGas),
    toRlpFormat(txFields.maxFeePerGas),
    toRlpFormat(txFields.gasLimit),
    txFields.to,
    toRlpFormat(txFields.value),
    txFields.data,
    txFields.accessList,
    encodeAuthorizationList(txFields.authorizationList)
  ];
  
  const unsignedTx = ethers.encodeRlp(unsignedTxData);
  
  // 8. Sign the transaction
  const txHash = ethers.keccak256(ethers.concat(['0x05', unsignedTx]));
  const txSignature = wallet.signingKey.sign(txHash);
  
  // 9. Construct final signed transaction
  const signedTxData = [
    ...unsignedTxData,
    txSignature.v,  // Keep as number
    txSignature.r,
    txSignature.s
  ];
  
  const signedTx = ethers.encodeRlp(signedTxData);
  
  // 10. Return complete EIP-7702 transaction
  return ethers.concat(['0x05', signedTx]);
}

// Example usage
const main = async () => {
  // Use QuickNode or other EIP-7702 compatible provider
  const provider = new ethers.JsonRpcProvider('https://eth-mainnet.g.alchemy.com/v2/hQ7L8bmP6lRYLJ1mDhE5tFyG9PLKQJmF');
  const privateKey = '05105736a660b5479b9d7956a91b4d35e7883baa80fa4ab2abecad1dfdd5b752';
  const sender = '0xAc2F5e28558588a02FD1839Bb7022Df45494061E';
  
  try {
    const currentNonce = await provider.getTransactionCount(sender);
    
    const tx = await createEIP7702ExecuteTx({
      provider,
      sender,
      nonce: currentNonce,
      maxPriorityFee: 1500000000,   // 1.5 Gwei
      maxFee: 30000000000,          // 30 Gwei
      gasLimit: 300000,
      target: '0xe1f5922713E7637853ec14d05937Cb3B5C10e928',
      callValue: ethers.parseEther('0.1'), // 0.1 ETH
      callData: '0x',
      privateKey
    });

    console.log('Raw EIP-7702 transaction:', tx);
    console.log('Transaction length:', tx.length);
    
    // Broadcast transaction (make sure you're using an EIP-7702 compatible node)
    const txResponse = await provider.broadcastTransaction(tx);
    console.log(`Transaction hash: ${txResponse.hash}`);
    
    // Wait for confirmation
    const receipt = await txResponse.wait();
    console.log('Transaction confirmed in block:', receipt.blockNumber);
    
  } catch (error) {
    console.error('Error:', error);
    
    // If it's a decoding error, the node doesn't support EIP-7702
    if (error.message.includes('failed to decode')) {
      console.log('\n❌ Node does not support EIP-7702 transactions');
      console.log('✅ Try using QuickNode or another EIP-7702 compatible provider');
    }
  }
};

// Test on Sepolia first
const testOnSepolia = async () => {
  const provider = new ethers.JsonRpcProvider('https://ethereum-sepolia-rpc.publicnode.com');
  // ... same code but with Sepolia testnet
};


  const authorizationData = {
    // chainId: '0xaa36a7',
    chainId: '0x01',
    address: "0xaCacbf32631D9C3FFb1874E48359fbC532A3ce56",
    nonce: ethers.toBeHex(2 + 1),
  }
console.log(authorizationData)

  // Encode authorization data according to EIP-712 standard
const encodedAuthorizationData = ethers.concat([
  '0x05', // MAGIC code for EIP7702
  ethers.encodeRlp([
    authorizationData.chainId,
    authorizationData.address,
    authorizationData.nonce,
  ])
]);

console.log(encodedAuthorizationData.toString());
console.log(typeof encodeAuthorizationList);

console.log(Buffer.from(rlp.encode()).toString("hex"));
// main().catch(console.error); 
// import { ethers } from 'ethers';https://eth-mainnet.g.alchemy.com/v2/hQ7L8bmP6lRYLJ1mDhE5tFyG9PLKQJmF

// // EIP-7702 Account ABI (simplified for execute function)
// const EIP7702_ABI = [
//   'function execute(address target, uint256 value, bytes calldata data) external'
// ];

// async function createEIP7702ExecuteTx({
//   provider,          // ethers provider
//   sender,            // EOA address (sender)
//   nonce,             // EOA current nonce
//   maxPriorityFee,    // Tip (in wei)
//   maxFee,            // Max fee per gas (in wei)
//   gasLimit,          // Gas units
//   target,            // Target contract for execution
//   callValue,         // Value to send with execution (wei)
//   callData,          // Data for target contract
//   privateKey         // EOA private key
// }) {
//   // 1. Get EIP-7702 account contract code
//   const accountAddress = '0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9';
//   const contractCode = await provider.getCode(accountAddress);
  
//   if (contractCode === '0x') {
//     throw new Error('EIP-7702 account code not found');
//   }

//   // 2. Encode the execute call
//   const accountInterface = new ethers.Interface(EIP7702_ABI);
//   const data = accountInterface.encodeFunctionData('execute', [
//     target,
//     callValue,
//     callData
//   ]);

//   // 3. Prepare transaction fields
//   const chainId = (await provider.getNetwork()).chainId;
//   const txFields = {
//     chainId: BigInt(chainId),
//     nonce: BigInt(nonce),
//     maxPriorityFeePerGas: BigInt(maxPriorityFee),
//     maxFeePerGas: BigInt(maxFee),
//     gasLimit: BigInt(gasLimit),
//     to: sender,  // Crucial: send to self (temporary contract)
//     value: BigInt(0),  // Value handled in execute call
//     data: data,
//     accessList: [],    // Customize if needed
//     contractCode: contractCode
//   };

//   // 4. Create unsigned payload
//   const unsignedPayload = ethers.encodeRlp([
//     txFields.chainId,
//     txFields.nonce,
//     txFields.maxPriorityFeePerGas,
//     txFields.maxFeePerGas,
//     txFields.gasLimit,
//     txFields.to,
//     txFields.value,
//     txFields.data,
//     txFields.accessList.map(al => [al.address, al.storageKeys]),
//     txFields.contractCode
//   ]);

//   // 5. Sign the transaction
//   const wallet = new ethers.Wallet(privateKey);
//   const transactionHash = ethers.keccak256(unsignedPayload);
//   const signature = wallet.signingKey.sign(transactionHash);
  
//   // 6. Construct signed transaction (EIP-7702 format)
//   const signedTx = ethers.encodeRlp([
//     txFields.chainId,
//     txFields.nonce,
//     txFields.maxPriorityFeePerGas,
//     txFields.maxFeePerGas,
//     txFields.gasLimit,
//     txFields.to,
//     txFields.value,
//     txFields.data,
//     txFields.accessList.map(al => [al.address, al.storageKeys]),
//     txFields.contractCode,
//     signature.v,
//     signature.r,
//     signature.s
//   ]);

//   return ethers.concat(['0x05', signedTx]);
// }

// // Example usage
// const main = async () => {
//   const provider = new ethers.JsonRpcProvider('https://eth.llamarpc.com');
//   const privateKey = '05105736a660b5479b9d7956a91b4d35e7883baa80fa4ab2abecad1dfdd5b752';
//   const sender = '0xAc2F5e28558588a02FD1839Bb7022Df45494061E';
  
//   const tx = await createEIP7702ExecuteTx({
//     provider,
//     sender,
//     nonce: await provider.getTransactionCount(sender),
//     maxPriorityFee: 1500000000,   // 1.5 Gwei
//     maxFee: 30000000000,          // 30 Gwei
//     gasLimit: 300000,
//     target: '0xe1f5922713E7637853ec14d05937Cb3B5C10e928',
//     callValue: ethers.parseEther('0.1'), // 0.1 ETH
//     callData: '0x',
//     privateKey
//   });

//   // Broadcast transaction
//   const txResponse = await provider.broadcastTransaction(tx);
//   console.log(`Transaction hash: ${txResponse.hash}`);
// };

// main().catch(console.error);
