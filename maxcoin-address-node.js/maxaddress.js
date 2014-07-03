// MaxCoin address generator
// Input a public key (base64 encoded) and the
// corresponding MaxCoin address will be
// generated
// Luke Mitchell July 2014

var sha3 = require('sha3');
var ripemd160 = require('ripemd160');
var bs58 = require('bs58');
var sha256 = require('sha256');

// in: binary string
// out: Buffer
var hash_sha256 = function(s) {
	return new Buffer(sha256(s), 'hex');
}

// in: string or Buffer
// out: Buffer
var hash_keccak = function(s) {
	var d = new sha3.SHA3Hash(256);
	d.update(s);
	return new Buffer(d.digest('hex'), 'hex'); 
};

// in: string or Buffer
// out: Buffer
var hash_ripemd160 = function(s) {
	return ripemd160(s);
};

// Address creation functions

var create_address = function(pubkey) {
	// hash public key
    // using RIPEMD160(SHA256(pubkey))	
	var baby = hash_sha256(pubkey);
	var child = hash_ripemd160(baby);

	// add version/network byte (base58 'm')
	var version = new Buffer(1);
	version[0] = 110;
	var teenager = Buffer.concat([version, child]);

	// hash this using Keccak
	var adult = hash_keccak(teenager);

	// take 4 bytes as checksum
	// append these to the end of the string
	var checksum = adult.slice(0, 4);
	var pensioner = Buffer.concat([teenager, checksum]);

	// base58 encode the address
	return bs58.encode(pensioner);
};

var validate_address = function(address) {
	var k = bs58.decode(address);
	var v0 = k.slice(0, 1);
	var data = k.slice(1, k.length - 4);
	var check0 = k.slice(k.length - 4);
	var check1 = hash_keccak(Buffer.concat([v0, data])).slice(0, 4);

	if (check0.toString('hex') != check1.toString('hex')) {
		console.log("Checksum error");
		return false;
	}

	if (110 != v0[0]) {
		console.log("Version mismatch");
		return false;
	}

	return true;
}

// Script entry point

// Base64 encoded public key
var pubkey_b64 = "BNX5V3mm0Uqu4ZVTB4AQ9IReam0vdsS3va8cuz4A909fVaJC2sqZcsnUL7sOWwz9U1HJehP0UW1tcfKvmfvAJkY=";
var pubkey = new Buffer(pubkey_b64, 'base64');

// MaxCoin address
var address = create_address(pubkey);
var success = validate_address(address);
console.log(address);
