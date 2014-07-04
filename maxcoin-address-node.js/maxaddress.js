// MaxCoin address generator
// Input a public key (base64 encoded) and the
// corresponding MaxCoin address will be
// generated
// Luke Mitchell July 2014

var sha3 = require('sha3');
var ripemd160 = require('ripemd160');
var bs58 = require('bs58');
var sha256 = require('sha256');
var jsrsasign = require('jsrsasign');

// Hashing functions

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

// Key generation functions

var create_keypair = function() {
	var keypair = jsrsasign.KEYUTIL.generateKeypair("EC", "secp256r1");
	// console.log(keypair.prvKeyObj.prvKeyHex);
	// console.log(keypair.pubKeyObj.pubKeyHex);
	return {prvKey: keypair.prvKeyObj.prvKeyHex, pubKey: keypair.pubKeyObj.pubKeyHex};
}

var prvKey_to_WIF = function(prvKey) {
	var baby = new Buffer(prvKey, 'hex');

	// add 0x80 to beginning
	var version = new Buffer(1);
	version[0] = 128; // 0x80
	var child = Buffer.concat([version, baby]);

	// hash the extended key
	var teenager = hash_keccak(child);

	// take first 4 bytes of second hash as checksum
	var checksum = teenager.slice(0, 4);

	// add checksum to end of extended key
	var adult = Buffer.concat([child, checksum]);

	// base58 encode
	return bs58.encode(adult);
}

var validate_WIF = function(wif) {
	// decode using base58
	var baby = bs58.decode(wif);

	// save the checksum bytes
	var check0 = baby.slice(baby.length - 4);

	// drop the checksum bytes
	var teenager = baby.slice(0, baby.length - 4);

	// hash the shortened string
	var adult = hash_keccak(teenager);

	// extract the second checksum
	var check1 = adult.slice(0, 4);

	if (check0.toString('hex') != check1.toString('hex')) {
		console.log("Checksum error");
		return false;
	}

	if (128 != baby[0]) {
		console.log("Version mismatch");
		return false;
	}

	return true;
}

var is_compressed_WIF = function(wif) {
	// first character should be a K or an L
	// rather than a 5
	if (wif[0] == '5') {
		return false;
	}

	if (wif[0] != 'K' && wif[0] != 'L') {
		console.log("Bad first character");
		return false;
	}

	// last byte when decoded should be 0x01
	var decoded = bs58.decode(wif);
	if (wif[wif.length - 1] != 0x01) {
		console.log("Bad final byte");
		return false;
	}

	return true;
}

var WIF_to_prvKey = function(wif) {
	// decode using base58
	var baby = bs58.decode(wif);

	// drop the checksum bytes
	var teenager = baby.slice(0, baby.length - 4);

	// drop the version byte
	var adult = teenager.slice(1);

	// drop last byte?
	if (is_compressed_WIF(wif)) {
		// TODO
		console.log("compressed!")
		return adult;
	} else {
		return adult;
	}
}

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

// Create a public/private keypair
console.log('Creating a MaxCoin address from a keypair...');

var keypair = create_keypair();
var wifKey = prvKey_to_WIF(keypair.prvKey);
var success = validate_WIF(wifKey);

console.log(keypair.prvKey);
console.log(WIF_to_prvKey(wifKey).toString('hex'));

var pubkey = new Buffer(keypair.pubKey, 'hex');

// Create a MaxCoin address from this keypair
var address = create_address(pubkey);
success = validate_address(address);

console.log('Address: ' + address);
console.log('Private key: ' + wifKey);
console.log();

// Base64 encoded public key
console.log('Creating a MaxCoin address from a public key...');

var pubkey_b64 = "BNX5V3mm0Uqu4ZVTB4AQ9IReam0vdsS3va8cuz4A909fVaJC2sqZcsnUL7sOWwz9U1HJehP0UW1tcfKvmfvAJkY=";
pubkey = new Buffer(pubkey_b64, 'base64');

// Create a MaxCoin address from this keypair
address = create_address(pubkey);
success = validate_address(address);

console.log('Address: ' + address);
console.log('Base64-encoded public key: ' + pubkey_b64);