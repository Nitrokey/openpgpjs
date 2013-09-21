// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA 

// The GPG4Browsers crypto interface

/**
 * Encrypts data using the specified public key multiprecision integers 
 * and the specified algorithm.
 * @param {Integer} algo Algorithm to be used (See RFC4880 9.1)
 * @param {openpgp_type_mpi[]} publicMPIs Algorithm dependent multiprecision integers
 * @param {openpgp_type_mpi} data Data to be encrypted as MPI
 * @return {(openpgp_type_mpi|openpgp_type_mpi[])} if RSA an openpgp_type_mpi; 
 * if elgamal encryption an array of two openpgp_type_mpi is returned; otherwise null
 */
function openpgp_crypto_asymetricEncrypt(algo, publicMPIs, data) {
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var n = publicMPIs[0].toBigInteger();
		var e = publicMPIs[1].toBigInteger();
		var m = data.toBigInteger();
		return rsa.encrypt(m,e,n).toMPI();
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
		var elgamal = new Elgamal();
		var p = publicMPIs[0].toBigInteger();
		var g = publicMPIs[1].toBigInteger();
		var y = publicMPIs[2].toBigInteger();
		var m = data.toBigInteger();
		return elgamal.encrypt(m,g,p,y);
	default:
		return null;
	}
}

/**
 * Decrypts data using the specified public key multiprecision integers of the private key,
 * the specified secretMPIs of the private key and the specified algorithm.
 * @param {Integer} algo Algorithm to be used (See RFC4880 9.1)
 * @param {openpgp_type_mpi[]} publicMPIs Algorithm dependent multiprecision integers 
 * of the public key part of the private key
 * @param {openpgp_type_mpi[]} secretMPIs Algorithm dependent multiprecision integers 
 * of the private key used
 * @param {openpgp_type_mpi} data Data to be encrypted as MPI
 * @return {BigInteger} returns a big integer containing the decrypted data; otherwise null
 */

function openpgp_crypto_asymetricDecrypt(algo, publicMPIs, secretMPIs, dataMPIs) {
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var d = secretMPIs[0].toBigInteger();
		var p = secretMPIs[1].toBigInteger();
		var q = secretMPIs[2].toBigInteger();
		var u = secretMPIs[3].toBigInteger();
		var m = dataMPIs[0].toBigInteger();
		return rsa.decrypt(m, d, p, q, u);
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
		var elgamal = new Elgamal();
		var x = secretMPIs[0].toBigInteger();
		var c1 = dataMPIs[0].toBigInteger();
		var c2 = dataMPIs[1].toBigInteger();
		var p = publicMPIs[0].toBigInteger();
		return elgamal.decrypt(c1,c2,p,x);
	default:
		return null;
	}
	
}

/**
 * generate random byte prefix as string for the specified algorithm
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes with length equal to the block
 * size of the cipher
 */
function openpgp_crypto_getPrefixRandom(algo) {
	switch(algo) {
	case 2:
	case 3:
	case 4:
		return openpgp_crypto_getRandomBytes(8);
	case 7:
	case 8:
	case 9:
	case 10:
		return openpgp_crypto_getRandomBytes(16);
	default:
		return null;
	}
}

/**
 * retrieve the MDC prefixed bytes by decrypting them
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @param {String} key Key as string. length is depending on the algorithm used
 * @param {String} data Encrypted data where the prefix is decrypted from
 * @return {String} Plain text data of the prefixed data
 */
function openpgp_crypto_MDCSystemBytes(algo, key, data) {
	util.print_debug_hexstr_dump("openpgp_crypto_symmetricDecrypt:\nencrypteddata:",data);
	switch(algo) {
	case 0: // Plaintext or unencrypted data
		return data;
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
		return openpgp_cfb_mdc(desede, 8, key, data, openpgp_cfb);
	case 3: // CAST5 (128 bit key, as per [RFC2144])
		return openpgp_cfb_mdc(cast5_encrypt, 8, key, data);
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
		return openpgp_cfb_mdc(BFencrypt, 8, key, data);
	case 7: // AES with 128-bit key [AES]
	case 8: // AES with 192-bit key
	case 9: // AES with 256-bit key
		return openpgp_cfb_mdc(AESencrypt, 16, keyExpansion(key), data);
	case 10: 
		return openpgp_cfb_mdc(TFencrypt, 16, key, data);
	case 1: // IDEA [IDEA]
		util.print_error(""+ (algo == 1 ? "IDEA Algorithm not implemented" : "Twofish Algorithm not implemented"));
		return null;
	default:
	}
	return null;
}
/**
 * Generating a session key for the specified symmetric algorithm
 * @param {Integer} algo Algorithm to use (see RFC4880 9.2)
 * @return {String} Random bytes as a string to be used as a key
 */
function openpgp_crypto_generateSessionKey(algo) {
	switch (algo) {
	case 2: // TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192)
	case 8: // AES with 192-bit key
		return openpgp_crypto_getRandomBytes(24); 
	case 3: // CAST5 (128 bit key, as per [RFC2144])
	case 4: // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
	case 7: // AES with 128-bit key [AES]
		util.print_debug("length = 16:\n"+util.hexstrdump(openpgp_crypto_getRandomBytes(16)));
		return openpgp_crypto_getRandomBytes(16);
	case 9: // AES with 256-bit key
	case 10:// Twofish with 256-bit key [TWOFISH]
		return openpgp_crypto_getRandomBytes(32);
	}
	return null;
}

/**
 * 
 * @param {Integer} algo public Key algorithm
 * @param {Integer} hash_algo Hash algorithm
 * @param {openpgp_type_mpi[]} msg_MPIs Signature multiprecision integers
 * @param {openpgp_type_mpi[]} publickey_MPIs Public key multiprecision integers 
 * @param {String} data Data on where the signature was computed on.
 * @return {Boolean} true if signature (sig_data was equal to data over hash)
 */
function openpgp_crypto_verifySignature(algo, hash_algo, msg_MPIs, publickey_MPIs, data) {
	var calc_hash = openpgp_crypto_hashData(hash_algo, data);
	switch(algo) {
	case 1: // RSA (Encrypt or Sign) [HAC]  
	case 2: // RSA Encrypt-Only [HAC]
	case 3: // RSA Sign-Only [HAC]
		var rsa = new RSA();
		var n = publickey_MPIs[0].toBigInteger();
		var e = publickey_MPIs[1].toBigInteger();
		var x = msg_MPIs[0].toBigInteger();
		var dopublic = rsa.verify(x,e,n);
		var hash  = openpgp_encoding_emsa_pkcs1_decode(hash_algo,dopublic.toMPI().substring(2));
		if (hash == -1) {
			util.print_error("PKCS1 padding in message or key incorrect. Aborting...");
			return false;
		}
		return hash == calc_hash;
		
	case 16: // Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
		util.print_error("signing with Elgamal is not defined in the OpenPGP standard.");
		return null;
	case 17: // DSA (Digital Signature Algorithm) [FIPS186] [HAC]
		var dsa = new DSA();
		var s1 = msg_MPIs[0].toBigInteger();
		var s2 = msg_MPIs[1].toBigInteger();
		var p = publickey_MPIs[0].toBigInteger();
		var q = publickey_MPIs[1].toBigInteger();
		var g = publickey_MPIs[2].toBigInteger();
		var y = publickey_MPIs[3].toBigInteger();
		var m = data;
		var dopublic = dsa.verify(hash_algo,s1,s2,m,p,q,g,y);
		return dopublic.compareTo(s1) == 0;
	default:
		return null;
	}
	
}
   
/**
 * Create a signature on data using the specified algorithm
 * @param {Integer} hash_algo hash Algorithm to use (See RFC4880 9.4)
 * @param {Integer} algo Asymmetric cipher algorithm to use (See RFC4880 9.1)
 * @param {openpgp_type_mpi[]} publicMPIs Public key multiprecision integers 
 * of the private key 
 * @param {openpgp_type_mpi[]} secretMPIs Private key multiprecision 
 * integers which is used to sign the data
 * @param {String} data Data to be signed
 * @return {(String|openpgp_type_mpi)}
 */
function openpgp_crypto_signData_own(algo, key, message) {
	var res = new openpgp_promise();
	var r;
	
	switch(algo.name) {
	case 'RSASSA-PKCS1-v1_5':
		m = openpgp_encoding_emsa_pkcs1_encode(8, util.bin2str(message), key.opgp.numBits / 8);
		rsa = new RSA();
		ss = rsa.sign(m, key.opgp.own.k.d, key.opgp.own.k.n);
		sb = ss.toByteArray();
		r = util.uint8concat([sb]);
		break;
	
	default:
		res._onerror('openpgp_crypto_signData_own(): unsupported algorithm ' + algo.name);
		return res;
	}

	res._oncomplete(r);
	return res;
}

/**
 * Create a hash on the specified data using the specified algorithm
 * @param {Integer} algo Hash algorithm type (see RFC4880 9.4)
 * @param {String} data Data to be hashed
 * @return {String} hash value
 */
function openpgp_crypto_hashData(algo, data) {
	var hash = null;
	switch(algo) {
	case 1: // - MD5 [HAC]
		hash = MD5(data);
		break;
	case 2: // - SHA-1 [FIPS180]
		hash = str_sha1(data);
		break;
	case 3: // - RIPE-MD/160 [HAC]
		hash = RMDstring(data);
		break;
	case 8: // - SHA256 [FIPS180]
		hash = str_sha256(data);
		break;
	case 9: // - SHA384 [FIPS180]
		hash = str_sha384(data);
		break;
	case 10:// - SHA512 [FIPS180]
		hash = str_sha512(data);
		break;
	case 11:// - SHA224 [FIPS180]
		hash = str_sha224(data);
	default:
		break;
	}
	return hash;
}

/**
 * Returns the hash size in bytes of the specified hash algorithm type
 * @param {Integer} algo Hash algorithm type (See RFC4880 9.4)
 * @return {Integer} Size in bytes of the resulting hash
 */
function openpgp_crypto_getHashByteLength(algo) {
	var hash = null;
	switch(algo) {
	case 1: // - MD5 [HAC]
		return 16;
	case 2: // - SHA-1 [FIPS180]
	case 3: // - RIPE-MD/160 [HAC]
		return 20;
	case 8: // - SHA256 [FIPS180]
		return 32;
	case 9: // - SHA384 [FIPS180]
		return 48
	case 10:// - SHA512 [FIPS180]
		return 64;
	case 11:// - SHA224 [FIPS180]
		return 28;
	}
	return null;
}

/**
 * Retrieve secure random byte string of the specified length
 * @param {Integer} length Length in bytes to generate
 * @return {String} Random byte string
 */
function openpgp_crypto_getRandomBytes(length) {
	var result = '';
	for (var i = 0; i < length; i++) {
		result += String.fromCharCode(openpgp_crypto_getSecureRandomOctet());
	}
	return result;
}

/**
 * Return a pseudo-random number in the specified range
 * @param {Integer} from Min of the random number
 * @param {Integer} to Max of the random number (max 32bit)
 * @return {Integer} A pseudo random number
 */
function openpgp_crypto_getPseudoRandom(from, to) {
	return Math.round(Math.random()*(to-from))+from;
}

/**
 * Return a secure random number in the specified range
 * @param {Integer} from Min of the random number
 * @param {Integer} to Max of the random number (max 32bit)
 * @return {Integer} A secure random number
 */
function openpgp_crypto_getSecureRandom(from, to) {
	var buf = new Uint32Array(1);
	window.crypto.getRandomValues(buf);
	var bits = ((to-from)).toString(2).length;
	while ((buf[0] & (Math.pow(2, bits) -1)) > (to-from))
		window.crypto.getRandomValues(buf);
	return from+(Math.abs(buf[0] & (Math.pow(2, bits) -1)));
}

function openpgp_crypto_getSecureRandomOctet() {
	var buf = new Uint32Array(1);
	window.crypto.getRandomValues(buf);
	return buf[0] & 0xFF;
}

/**
 * Create a secure random big integer of bits length
 * @param {Integer} bits Bit length of the MPI to create
 * @return {BigInteger} Resulting big integer
 */
function openpgp_crypto_getRandomBigInteger(bits) {
	if (bits < 0)
	   return null;
	var numBytes = Math.floor((bits+7)/8);

	var randomBits = openpgp_crypto_getRandomBytes(numBytes);
	if (bits % 8 > 0) {
		
		randomBits = String.fromCharCode(
						(Math.pow(2,bits % 8)-1) &
						randomBits.charCodeAt(0)) +
			randomBits.substring(1);
	}
	return new openpgp_type_mpi().create(randomBits).toBigInteger();
}

function openpgp_crypto_getRandomBigIntegerInRange(min, max) {
	if (max.compareTo(min) <= 0)
		return;
	var range = max.subtract(min);
	var r = openpgp_crypto_getRandomBigInteger(range.bitLength());
	while (r > range) {
		r = openpgp_crypto_getRandomBigInteger(range.bitLength());
	}
	return min.add(r);
}


//This is a test method to ensure that encryption/decryption with a given 1024bit RSAKey object functions as intended
function openpgp_crypto_testRSA(key){
	debugger;
    var rsa = new RSA();
	var mpi = new openpgp_type_mpi();
	mpi.create(openpgp_encoding_eme_pkcs1_encode('ABABABAB', 128));
	var msg = rsa.encrypt(mpi.toBigInteger(),key.ee,key.n);
	var result = rsa.decrypt(msg, key.d, key.p, key.q, key.u);
}

function openpgp_crypto_stashKey_own(pair, numBits){
	/**
	 * OK, so this kind of "hopes" that no one imports keys from
	 * a different origin into ours.  Let's keep hoping so.
	 */
	var priv = pair.privateKey, pub = pair.publicKey;
	var aid, val;
	switch (priv.algorithm.name) {
		case 'RSASSA-PKCS1-v1_5':
		case 'RSAES-PKCS1-v1_5':
			aid = priv.opgp.own.k.n.toString(16).substring(0, 16);
			val = {
				type: 'RSA',
				numBits: numBits,
				privExtractable: priv.extractable,
				pubExtractable: pub.extractable,
				d: priv.opgp.own.k.d.toString(32),
				e: priv.opgp.own.k.e.toString(32),
				n: priv.opgp.own.k.n.toString(32),
				p: priv.opgp.own.k.p.toString(32),
				q: priv.opgp.own.k.q.toString(32),
				u: priv.opgp.own.k.u.toString(32)
			};
			break;

		default:
			return 'openpgp_crypto_stashKey_own: unsupported algorithm ' + priv.algorithm.name;
	}
	val = JSON.stringify(val);

	var aname = priv.algorithm.name.replace(/[^A-Za-z0-9_]/g, '');

	var kname = "openpgp.own.key.a" + aname + ".s" + numBits + ".k" + aid;
	var cid = window.localStorage[kname + ".last"];
	if (cid == null)
		id = 0;
	else
		id = parseInt(cid, 10) + 1;
	window.localStorage[kname + ".last"] = id.toString();
	window.localStorage[kname + "." + id] = val;
	window.localStorage["openpgp.own.key.last.a" + aname + ".s" + numBits] = kname;

	priv.name = kname + ".tv";
	priv.id = id;
	pub.name = kname + ".tp";
	pub.id = id;
	return null;
}

var _openpgp_crypto_getAllKeys_pat = new RegExp('^(openpgp\.own\.key\.a.*)\.([0-9]+)$');

function openpgp_crypto_getAllKeys_own() {
	var name, arr, res;

	res = new openpgp_promise();
	arr = [];
	for (name in window.localStorage) {
		var m = name.match(_openpgp_crypto_getAllKeys_pat);
		if (!m)
			continue;
		var val = window.localStorage[name];
		var pair = openpgp_crypto_digKeyPairFromJSON_own(val, m[1], m[2]);

		if (pair.publicKey != null) {
			pair.publicKey.name = m[1] + ".tp";
			pair.publicKey.id = m[2];
			arr[arr.length] = pair.publicKey;
		}
		if (pair.privateKey != null) {
			pair.privateKey.name = m[1] + ".tv";
			pair.privateKey.id = m[2];
			arr[arr.length] = pair.privateKey;
		}
	}

	res._oncomplete({ target: { result: arr } });
	return res;
}

function openpgp_crypto_getKeyByName_own(name) {
	var res = new openpgp_promise();

	if (name == null)
		return openpgp_crypto_getAllKeys_own();

	var prefix = "openpgp.own.key.a";
	if (name.substring(0, prefix.length) != prefix) {
		res._onerror({ target: { result: 'Invalid structure for an owncrypto key name at the start' } });
		return res;
	}
	var type = name.substring(name.length - 3);
	if (type != ".tv" && type != ".tp") {
		res._onerror({ target: { result: 'Invalid key type in an owncrypto key name' } });
		return res;
	}

	var kname = name.substring(0, name.length - 3);
	var last = window.localStorage[kname + ".last"];
	if (last == null) {
		res._oncomplete({ target: { result: [] } });
		return res;
	}
	var arr = [];
	for (var i = 0; i <= last; i++) {
		var keyname = kname + '.' + i;
		var val = window.localStorage[keyname];
		if (val == null) {
			res._onerror({ target: { result: 'Internal error in openpgp_crypto_getKeyByName_own(): no window.localStorage["' + keyname + '"] while last is ' + last } });
			return res;
		}
		pair = openpgp_crypto_digKeyPairFromJSON_own(val, kname, i);
		if (type == ".tv") {
			pair.privateKey.name = name;
			pair.privateKey.id = i;
			arr[arr.length] = pair.privateKey;
		} else {
			pair.publicKey.name = name;
			pair.publicKey.id = i;
			arr[arr.length] = pair.publicKey;
		}
	}
	res._oncomplete({ target: { result: arr } });
	return res;
}

function openpgp_crypto_pair_from_RSA(key, numBits, algo, privKeyUsage, publicKeyUsage) {
	var pair = new openpgp_keypair();

	pair.privateKey = {
		type: 'private',
		extractable: true,
		algorithm: algo,
		keyUsage: privKeyUsage,
		opgp: {
			own: {
				k: key
			},
			numBits: numBits
		}
	};
	pair.publicKey = {
		type: 'public',
		extractable: true,
		algorithm: algo,
		keyUsage: publicKeyUsage,
		opgp: {
			own: {
				k: key
			},
			numBits: numBits
		}
	};
	openpgp_webcrypto_tag_pair(pair, numBits, "owncrypto");
	return pair;
}

function openpgp_crypto_digKey_own(algo, numBits) {
	var aname = algo.name.replace(/[^A-Za-z0-9_]/g, '');
	var kname = window.localStorage["openpgp.own.key.last.a" + aname + ".s" + numBits];
	if (kname == null)
		return null;
	var id = window.localStorage[kname + ".last"];
	if (id == null) {
		console.error("OpenPGP.js error: no stashed " + kname + ".last member");
		return null;
	}
	var val = window.localStorage[kname + "." + id];
	if (val == null) {
		console.error("OpenPGP.js error: no stashed " + kname + "." + id + " member");
		return null;
	}
	return openpgp_crypto_digKeyPairFromJSON_own(val, kname, id);
}

function openpgp_crypto_digKeyPairFromJSON_own(val, kname, id) {
	var algoShort, numBits, pieces;
	pieces = kname.split('.');
	if (pieces.length < 5 || pieces[0] != 'openpgp' || pieces[1] != 'own' || pieces[2] != 'key' || pieces[3][0] != 'a' || pieces[4][0] != 's') {
		console.error("OpenPGP.js error: invalid stashed key name " + kname);
		return null;
	}
	algoShort = pieces[3].substring(1);
	numBits = pieces[4].substring(1);

	var res = JSON.parse(val);
	if (res == null) {
		console.error("OpenPGP.js error: invalid JSON data for stashed " + kname + "." + id);
		return null;
	}

	var pair;
	var privKeyUsage = null, pubKeyUsage = null;

	algo = { 'name': null };

	switch (algoShort) {
		case 'RSASSAPKCS1v1_5':
			algo.name = 'RSASSA-PKCS1-v1_5';
			privKeyUsage = ['sign'];
			pubKeyUsage = ['verify'];
			/* FALLTHROUGH */

		case 'RSAESPKCS1v1_5':
			if (privKeyUsage == null) {
				algo.name = 'RSAES-PKCS1-v1_5';
				privKeyUsage = ['decrypt'];
				pubKeyUsage = ['encrypt'];
			}

			if (res.type != "RSA") {
				console.error("OpenPGP.js error: wrong type for stashed " + kname + "." + id + ": expected RSA, got " + res.type);
				return null;
			}

			rsa = new RSA();
			key = new rsa.keyObject();
			key.ee = new BigInteger(res.e, 32);
			key.e = parseInt(key.e.toString(16), 16);
			key.p = new BigInteger(res.p, 32);
			key.q = new BigInteger(res.q, 32);
			if (!rsa.finalize_check(key)) {
				console.error("OpenPGP.js error: finalize_check() failed for stashed " + kname + "." + id);
				return null;
			}

			pair = openpgp_crypto_pair_from_RSA(key, numBits, algo, privKeyUsage, pubKeyUsage);
			pair.privateKey.extractable = res.privExtractable;
			pair.publicKey.extractable = res.pubExtractable;
			break;

		default:
			console.error("OpenPGP.js error: don't know how to dig up a " + algoShort + " key from the stash");
			return null;
	}
	return pair;
}

/**
 * Calls the necessary crypto functions to generate a keypair. 
 * Called directly by openpgp.js
 * @param {Integer} keyType Follows OpenPGP algorithm convention.
 * @param {Integer} numBits Number of bits to make the key to be generated
 * @return {openpgp_keypair}
 */
function openpgp_crypto_generateKeyPair_own(algo, extractable, passphrase, s2kHash, symmetricEncryptionAlgorithm){
	var res = new openpgp_promise();
	var numBits, pair;
	var privKeyUsage = null, pubKeyUsage = null;

	switch(algo.name){
	case 'RSASSA-PKCS1-v1_5':
	    privKeyUsage = ['sign'];
	    pubKeyUsage = ['verify'];
	    /* FALLTHROUGH */

	case 'RSAES-PKCS1-v1_5':
	    if (privKeyUsage == null) {
		privKeyUsage = ['decrypt'];
		pubKeyUsage = ['encrypt'];
	    }
	    numBits = algo.params.modulusLength;
	    var rsa = new RSA();
	    var key = rsa.generate(algo.params.modulusLength, util.hexidump(algo.params.publicExponent));
	    pair = openpgp_crypto_pair_from_RSA(key, numBits, algo, privKeyUsage, pubKeyUsage);
	    pair.privateKey.extractable = extractable;
	    pair.publicKey.extractable = true;
	    break;

	default:
	    res._onerror("Unknown algorithm " + algo.name);
	    return res;
	}

	err = openpgp_crypto_stashKey_own(pair, numBits);
	if (err != null) {
		res._onerror(err);
		return res;
	}

	res._oncomplete(pair);
	return res;
}

function openpgp_crypto_exportKey_own(format, key) {
	var res = new openpgp_promise();
	var arr;

	if (!key.extractable) {
		res._onerror('Key not extractable');
		return res;
	}
	if (!(key.type == 'public' && format == 'spki') &&
	    !(key.type == 'private' && format == 'pkcs8')) {
		res._onerror('Invalid format/keytype combination, only spki/public and pkcs8/private supported so far');
		return res;
	}

	switch (key.algorithm.name) {
		case 'RSASSA-PKCS1-v1_5':
		case 'RSAES-PKCS1-v1_5':
			var d = new openpgp_encoding_der();
			if (format == 'spki') {
				arr = d.build("sequence", [
					d.build("sequence", [
						d.build("objectIdentifier", [42, 134, 72, 134, 247, 13, 1, 1, 1]),
						d.build("null")
					]),
					d.build("bitString",
						d.build("sequence", [
							d.build("integer", key.opgp.own.k.n.toByteArray()),
							d.build("integer", key.opgp.own.k.ee.toByteArray())
						])
					)
				]);
			} else if (format == "pkcs8") {
				arr = d.build("sequence", [
					d.build("integer", [0]),
					d.build("sequence", [
						d.build("objectIdentifier", [42, 134, 72, 134, 247, 13, 1, 1, 1]),
						d.build("null")
					]),
					d.build("octetString",
						d.build("sequence", [
							d.build("integer", [0]),
							d.build("integer", key.opgp.own.k.n.toByteArray()),
							d.build("integer", key.opgp.own.k.ee.toByteArray()),
							d.build("integer", key.opgp.own.k.d.toByteArray()),
							d.build("integer", key.opgp.own.k.p.toByteArray()),
							d.build("integer", key.opgp.own.k.q.toByteArray()),
							d.build("integer", key.opgp.own.k.dmp1.toByteArray()),
							d.build("integer", key.opgp.own.k.dmq1.toByteArray()),
							d.build("integer", key.opgp.own.k.u.toByteArray())
						])
					)
				]);
			}
			break;

		default:
			res._onerror('openpgp_crypto_exportKey_own(): unsupported algorithm ' + key.algorithm.name);
			return res;
	}

	res._oncomplete(arr);
	return res;
}
