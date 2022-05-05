// Utilities for WTF protocol
// by Nanak Nihal Khalsa

var Buffer = require('safe-buffer').Buffer

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
exports.searchForPlainTextInBase64 = function (plaintext, base64string) {
    // convert both to bytes, so there is no difference between base64 and plaintext -- this difference is only in interperetation of the bytes, not the bytes themselves:
    let searchBytes = Buffer.from(plaintext).toString('hex');
    let allBytes = Buffer.from(base64string, 'base64').toString('hex');
    let start = allBytes.indexOf(searchBytes)
    if (start == -1) { return null }
    let finish = start + searchBytes.length
    return [start / 2, finish / 2]; //convert nibbles to bytes by dividing by 2
},

exports.searchForPlainTextInBase64Url = function (plaintext, base64UrlString) {
    searchForPlainTextInBase64(plaintext, base64UrlString.replaceAll('-', '+').replaceAll('_', '/'))
}

exports.padBase64 = function(base64string) {
  return btoa(atob(base64string))
}
// Make sure it does bottomBread + id + topBread and does not allow any other text in between. If Google changes their JWT format so that the sandwich now contains other fields between bottomBread and topBread, this should fail until the contract is updated. 
exports.sandwichIDWithBreadFromContract = async function (id, contract) {
  let sandwich = (await contract.bottomBread()) + Buffer.from(id).toString('hex') + (await contract.topBread());
  sandwich = sandwich.replaceAll('0x', '');
  return sandwich
}

exports.hexToString = function(hex) {
  return Buffer.from(hex.replace('0x',''), 'hex').toString()
}

// TODO: better error handling
// takes encoded JWT and returns parsed header, parsed payload, parsed signature, raw header, raw header, raw signature
exports.parseJWT = (JWT) => {
  if(!JWT){return null}
  let parsedToJSON = {}
  JWT.split('&').map(x=>{let [key, value] = x.split('='); parsedToJSON[key] = value});
  let [rawHead, rawPay, rawSig] = parsedToJSON['id_token'].split('.');
  console.log(rawHead, rawPay, 'RAWR')
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