// Utilities for WTF protocol
// by Nanak Nihal Khalsa

var Buffer = require('safe-buffer').Buffer
const { ethers } = require('ethers')

exports.fixedBufferXOR = function (a, b) {
  // pad the shorter buffer with 0s
  let padded
  let a_
  let b_
  if(a.length > b.length){
    padded = Buffer.alloc(a.length)
    a_ = a
    b.copy(padded, padded.length-b.length)
    b_ = padded

  } else if(a.length < b.length){
    padded = Buffer.alloc(b.length)
    a_ = a.copy(padded, padded.length-a.length)
    a_ = padded
    b_ = b
  } else {
    a_ = a;
    b_ = b;
  }

  var length = a_.length
  var buffer = Buffer.allocUnsafe(length)

  for (var i = 0; i < length; ++i) {
    buffer[i] = a_[i] ^ b_[i]
  }
  return buffer
}


// Note: this is fairly untested currently
// arguments: plaintext, base64string
const searchForPlainTextInBase64 = function (plaintext, base64string) {
    // convert both to bytes, so there is no difference between base64 and plaintext -- this difference is only in interperetation of the bytes, not the bytes themselves:
    let searchBytes = Buffer.from(plaintext).toString('hex');
    let allBytes = Buffer.from(base64string, 'base64').toString('hex');
    let start = allBytes.indexOf(searchBytes)
    if (start == -1) { return null }
    let finish = start + searchBytes.length
    return [start / 2, finish / 2]; //convert nibbles to bytes by dividing by 2
}

exports.searchForPlainTextInBase64 = searchForPlainTextInBase64

exports.searchForPlainTextInBase64Url = function (plaintext, base64UrlString) {
    searchForPlainTextInBase64(plaintext, base64UrlString.replaceAll('-', '+').replaceAll('_', '/'))
}

exports.padBase64 = function(base64string) {
  return btoa(atob(base64string))
}

// Sandwiches data between contract.bottomBread() and contract.topBread(). By default does ID with id bread. If type='exp' is specified, it will sandwich with the expiration bread
const sandwichDataWithBreadFromContract = async (data, contract, type='id') => {
  let bottomBread; 
  let topBread;
  if(type == 'id') {
    bottomBread = await contract.bottomBread()
    topBread = await contract.topBread()
  } else if(type == 'exp') {
    bottomBread = await contract.expBottomBread()
    topBread = await contract.expTopBread()
  } else {
    throw new Error(`type "${type}" not recognized`)
  }

  let sandwich = bottomBread + Buffer.from(data).toString('hex') + topBread;
  sandwich = sandwich.replaceAll('0x', '');
  return sandwich
}

exports.sandwichDataWithBreadFromContract = sandwichDataWithBreadFromContract;

exports.hexToString = function(hex) {
  return Buffer.from(hex.replace('0x',''), 'hex').toString()
}

// TODO: better error handling
// takes encoded JWT and returns parsed header, parsed payload, parsed signature, raw header, raw header, raw signature
const parseJWT = (jwt) => {
  let [rawHead, rawPay, rawSig] = jwt.split('.');
  let [head, pay] = [rawHead, rawPay].map(x => x ? JSON.parse(atob(x)) : null);
  let [sig] = [Buffer.from(rawSig.replaceAll('-', '+').replaceAll('_', '/'), 'base64')] //replaceAlls convert it from base64url to base64
  return {
    'header' :  {
      'parsed' : head,
     'raw' : rawHead,
    }, 
    'payload' :  {
      'parsed' : pay,
     'raw' : rawPay,
    }, 
    'signature' :  {
      'decoded' : sig,
     'raw' : rawSig,
    }, 
  }
}

exports.parseJWT = parseJWT;

const sha256FromString = str => ethers.utils.sha256(ethers.utils.toUtf8Bytes(str));
exports.sha256FromString = sha256FromString;

const keccak256FromString = str => ethers.utils.keccak256(ethers.utils.toUtf8Bytes(str));
exports.keccak256FromString = keccak256FromString;

// @param {string} address
// @param {string} message
// Returns two commits: [unbound, bound]. The unbound commit is the hash of the message. The bound commit is the hash of the message concatenated with the address
// It is important to use the Keccak256 algorithm or any that doesn't rely on the Merkle-Dagmard transform to prevent length extension attacks
const generateCommitments = (address, message) => {
  let addr_ = Buffer.from(address.replace('0x', ''), 'hex')
  let msg_ = Buffer.from(message)
  let unbound = ethers.utils.keccak256(msg_)
  let bound = ethers.utils.keccak256(Buffer.concat([msg_, addr_]))
  return [unbound, bound]
}
exports.generateCommitments = generateCommitments;

// @param {VerifyJWT} vjwt is the VerifyJWT
// @param {string} jwt is the JWT with base64url-encoded header, payload, and signature joined by '.'
// @param {string} idFieldName is the JWT's claim for the id (likely 'sub' or 'email')
// @param {env} hardhat || ethersjs. If hardhat, will return structs in hardhat format. If ethersjs, will return structs in ethersjs format (yes, they are / were different formats at the time of writing)
exports.getParamsForVerifying = async (vjwt, jwt, idFieldName, type='hardhat') => {
      let params = {}; 
      const parsed = parseJWT(jwt)

      params.id = parsed.payload.parsed[idFieldName]
      params.expTimeInt = parsed.payload.parsed.exp
      params.expTime = params.expTimeInt.toString()
      

      // Signature of JWT in ethers-compatible format
      params.signature = ethers.BigNumber.from(parsed.signature.decoded)

      // Message and hashedMessage needed for proof (message is header.payload)
      params.message = parsed.header.raw + '.' + parsed.payload.raw
      params.hashedMessage = sha256FromString(params.message)

      // Where payload starts
      params.payloadIdx = Buffer.from(parsed.header.raw).length + 1 //Buffer.from('.').length == 1
  
      // Find ID and exp sandwiches (and make a bad one for testing purposes to make sure it fails)
      const idSandwichValue = await sandwichDataWithBreadFromContract(params.id, vjwt, type='id');
      const expSandwichValue = await sandwichDataWithBreadFromContract(params.expTime, vjwt, type='exp');
      // aud isn't quite a sandwich but is treated similarly
      const audSandwichValue = (await vjwt.aud()).replace('0x', '');

      // Find indices of sandwich in raw payload:
      const idSandwichText = Buffer.from(idSandwichValue, 'hex').toString()
      const expSandwichText = Buffer.from(expSandwichValue, 'hex').toString()
      const audSandwichText = Buffer.from(audSandwichValue, 'hex').toString()

      let startIdxID; let endIdxID; let startIdxExp; let endIdxExp; 
      try {
        [startIdxID, endIdxID] = searchForPlainTextInBase64(idSandwichText, parsed.payload.raw)
      } catch(err) {
        console.error(err)
        console.error(`There was a problem searching for: ${(idSandwichText)} \n in ${Buffer.from(parsed.payload.raw, 'base64').toString()}`)
      }

      try {
        [startIdxExp, endIdxExp] = searchForPlainTextInBase64(expSandwichText, parsed.payload.raw)
      } catch(err) {
        console.error(err)
        console.error(`There was a problem searching for: ${(expSandwichText)} \n in ${Buffer.from(parsed.payload.raw, 'base64').toString()}`)
      }

      try {
        [startIdxAud, endIdxAud] = searchForPlainTextInBase64(audSandwichText, parsed.payload.raw)
      } catch(err) {
        console.error(err)
        console.error(`There was a problem searching for: ${(audSandwichText)} \n in ${Buffer.from(parsed.payload.raw, 'base64').toString()}`)
      }
      
            
      // Generate the actual sandwich struct
      params.proposedIDSandwich = {
        idxStart: startIdxID, 
        idxEnd: endIdxID, 
        sandwichValue: Buffer.from(idSandwichValue, 'hex')
      } 
      params.proposedExpSandwich = {
        idxStart: startIdxExp, 
        idxEnd: endIdxExp, 
        sandwichValue: Buffer.from(expSandwichValue, 'hex')
      } 
      params.proposedAud = {
        idxStart: startIdxAud, 
        idxEnd: endIdxAud, 
        sandwichValue: Buffer.from(audSandwichValue, 'hex')
      } 

      // Generates a proof to be commited that the entity owning *address* knows the JWT
      // params.generateProof = async (address) => ethers.utils.sha256(
      //                                                                 await xor(Buffer.from(params.hashedMessage.replace('0x', ''), 'hex'), 
      //                                                                           Buffer.from(address.replace('0x', ''), 'hex')
      //                                                                           )
      //                                                     )

      params.generateCommitments = address => generateCommitments(address, params.message)

      params.verifyMeContractParams = () => [
        params.signature, 
        params.message, 
        params.payloadIdx, 
        params.proposedIDSandwich, 
        params.proposedExpSandwich,
        params.proposedAud
    ]

      const p = params
      return p
}