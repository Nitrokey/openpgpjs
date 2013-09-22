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

/**
 * @class
 * @classdesc The class that deals with storage of the keyring. Currently the only option is to use HTML5 local storage.
 */
function openpgp_keyring() {
		
	/**
	 * Initialization routine for the keyring. This method reads the 
	 * keyring from HTML5 local storage and initializes this instance.
	 * This method is called by openpgp.init().
	 */
	function init() {
		var sprivatekeys = JSON.parse(window.localStorage.getItem("privatekeys"));
		var spublickeys = JSON.parse(window.localStorage.getItem("publickeys"));
		if (sprivatekeys == null || sprivatekeys.length == 0) {
			sprivatekeys = new Array();
		}

		if (spublickeys == null || spublickeys.length == 0) {
			spublickeys = new Array();
		}
		this.publicKeys = new Array();
		this.privateKeys = new Array();
		var k = 0;
		for (var i =0; i < sprivatekeys.length; i++) {
			var r = openpgp.read_privateKey(sprivatekeys[i]);
			this.privateKeys[k] = { armored: sprivatekeys[i], obj: r[0], keyId: r[0].getKeyId()};
			k++;
		}
		k = 0;
		for (var i =0; i < spublickeys.length; i++) {
			var r = openpgp.read_publicKey(spublickeys[i]);
			if (r[0] != null) {
				this.publicKeys[k] = { armored: spublickeys[i], obj: r[0], keyId: r[0].getKeyId()};
				k++;
			}
		}
	}
	this.init = init;

	/**
	 * Checks if at least one private key is in the keyring
	 * @return {Boolean} True if there are private keys, else false.
	 */
	function hasPrivateKey() {
		return this.privateKeys.length > 0;
	}
	this.hasPrivateKey = hasPrivateKey;

	/**
	 * Saves the current state of the keyring to HTML5 local storage.
	 * The privateKeys array and publicKeys array gets Stringified using JSON
	 */
	function store() { 
		var priv = new Array();
		for (var i = 0; i < this.privateKeys.length; i++) {
			priv[i] = this.privateKeys[i].armored;
		}
		var pub = new Array();
		for (var i = 0; i < this.publicKeys.length; i++) {
			pub[i] = this.publicKeys[i].armored;
		}
		window.localStorage.setItem("privatekeys",JSON.stringify(priv));
		window.localStorage.setItem("publickeys",JSON.stringify(pub));
	}
	this.store = store;
	/**
	 * searches all public keys in the keyring matching the address or address part of the user ids
	 * @param {String} email_address
	 * @return {openpgp_msg_publickey[]} The public keys associated with provided email address.
	 */
	function getPublicKeyForAddress(email_address) {
		var results = new Array();
		var spl = email_address.split("<");
		var email = "";
		if (spl.length > 1) {
			email = spl[1].split(">")[0];
		} else {
			email = email_address.trim();
		}
		email = email.toLowerCase();
		if(!util.emailRegEx.test(email)){
		    return results;
		}
		for (var i =0; i < this.publicKeys.length; i++) {
			for (var j = 0; j < this.publicKeys[i].obj.userIds.length; j++) {
				if (this.publicKeys[i].obj.userIds[j].text.toLowerCase().indexOf(email) >= 0)
					results[results.length] = this.publicKeys[i];
			}
		}
		return results;
	}
	this.getPublicKeyForAddress = getPublicKeyForAddress;

	/**
	 * Searches the keyring for a private key containing the specified email address
	 * @param {String} email_address email address to search for
	 * @return {openpgp_msg_privatekey[]} private keys found
	 */
	function getPrivateKeyForAddress(email_address) {
		var results = new Array();
		var spl = email_address.split("<");
		var email = "";
		if (spl.length > 1) {
			email = spl[1].split(">")[0];
		} else {
			email = email_address.trim();
		}
		email = email.toLowerCase();
		if(!util.emailRegEx.test(email)){
		    return results;
		}
		for (var i =0; i < this.privateKeys.length; i++) {
			for (var j = 0; j < this.privateKeys[i].obj.userIds.length; j++) {
				if (this.privateKeys[i].obj.userIds[j].text.toLowerCase().indexOf(email) >= 0)
					results[results.length] = this.privateKeys[i];
			}
		}
		return results;
	}

	this.getPrivateKeyForAddress = getPrivateKeyForAddress;
	/**
	 * Searches the keyring for public keys having the specified key id
	 * @param {String} keyId provided as string of hex number (lowercase)
	 * @return {openpgp_msg_privatekey[]} public keys found
	 */
	function getPublicKeysForKeyId(keyId) {
		var result = new Array();
		for (var i=0; i < this.publicKeys.length; i++) {
			var key = this.publicKeys[i];
			if (keyId == key.obj.getKeyId())
				result[result.length] = key;
			else if (key.obj.subKeys != null) {
				for (var j=0; j < key.obj.subKeys.length; j++) {
					var subkey = key.obj.subKeys[j];
					if (keyId == subkey.getKeyId()) {
						result[result.length] = {
								obj: key.obj.getSubKeyAsKey(j),
								keyId: subkey.getKeyId()
						}
					}
				}
			}
		}
		return result;
	}
	this.getPublicKeysForKeyId = getPublicKeysForKeyId;
	
	/**
	 * Searches the keyring for private keys having the specified key id
	 * @param {String} keyId 8 bytes as string containing the key id to look for
	 * @return {openpgp_msg_privatekey[]} private keys found
	 */
	function getPrivateKeyForKeyId(keyId) {
		var result = new Array();
		for (var i=0; i < this.privateKeys.length; i++) {
			if (keyId == this.privateKeys[i].obj.getKeyId()) {
				result[result.length] = { key: this.privateKeys[i], keymaterial: this.privateKeys[i].obj.privateKeyPacket};
			}
			if (this.privateKeys[i].obj.subKeys != null) {
				var subkeyids = this.privateKeys[i].obj.getSubKeyIds();
				for (var j=0; j < subkeyids.length; j++)
					if (keyId == util.hexstrdump(subkeyids[j])) {
						result[result.length] = { key: this.privateKeys[i], keymaterial: this.privateKeys[i].obj.subKeys[j]};
					}
			}
		}
		return result;
	}
	this.getPrivateKeyForKeyId = getPrivateKeyForKeyId;
	
	/**
	 * Imports a public key from an exported ascii armored message 
	 * @param {String} armored_text PUBLIC KEY BLOCK message to read the public key from
	 */
	function importPublicKey (armored_text) {
		var result = openpgp.read_publicKey(armored_text);
		for (var i = 0; i < result.length; i++) {
			this.publicKeys[this.publicKeys.length] = {armored: armored_text, obj: result[i], keyId: result[i].getKeyId()};
		}
		return true;
	}

	/**
	 * Imports a private key from an exported ascii armored message 
	 * @param {String} armored_text PRIVATE KEY BLOCK message to read the private key from
	 */
	function importPrivateKey (armored_text, password, nonextractable) {
		var result = openpgp.read_privateKey(armored_text);
		if(!nonextractable && !result[0].decryptSecretMPIs(password))
		    return false;
		for (var i = 0; i < result.length; i++) {
			this.privateKeys[this.privateKeys.length] = {armored: armored_text, obj: result[i], keyId: result[i].getKeyId()};
		}
		return true;
	}

	this.importPublicKey = importPublicKey;
	this.importPrivateKey = importPrivateKey;

	function importWebCryptoKeyPair (pair) {
		var res = new openpgp_promise();

		if (pair.publicKeyArmored == null) {
			res._onerror({ target: { result: 'No armored public key passed to importWebCryptoKeyPair(' + pair.id + ')' } });
			return res;
		} else if (pair.privateKeyArmored == null) {
			res._onerror({ target: { result: 'No armored private key passed to importWebCryptoKeyPair(' + pair.id + ')' } });
			return res;
		}
		if (!this.importPublicKey(pair.publicKeyArmored)) {
			res._onerror({ target: { result: 'Failed to import the public key for ' + pair.id + ' into the keyring' } });
			return res;
		}
		if (!this.importPrivateKey(pair.privateKeyArmored, '', !pair.privateKey.extractable)) {
			res._onerror({ target: { result: 'Failed to import the private key for ' + pair.id + ' into the keyring' } });
			return res;
		}

		var subkeys = [];
		for (var name in pair.subKeys)
			if (pair.subKeys.hasOwnProperty(name))
				subkeys[subkeys.length] = pair.subKeys[name];
		var idx = 0;
		var self = this;
		function next_subkey() {
			if (idx == subkeys.length)
				res._oncomplete(true);
			else
				self.importWebCryptoKeyPair(subkeys[idx++]).then(
					next_subkey,
					function (e) { res._onerror(e); }
				);
		}
		next_subkey();

		return res;
	}
	this.importWebCryptoKeyPair = importWebCryptoKeyPair;

	function getWebCryptoPairById(id) {
		var res = new openpgp_promise();

		id = id.toUpperCase();

		var privKey;
		for (var i = 0; i < this.privateKeys.length; i++) {
			var k = this.privateKeys[i];
			if (id == util.hexstrdump(k.keyId).toUpperCase() ||
			    id == util.hexstrdump(k.obj.getFingerprint()).toUpperCase()) {
				privKey = k;
				break;
			}
		}
		if (privKey == null) {
			res._oncomplete({ target: { result: null } });
			return res;
		}

		var pubKey;
		for (var i = 0; i < this.publicKeys.length; i++) {
			var k = this.publicKeys[i];
			if (id == util.hexstrdump(k.keyId).toUpperCase() ||
			    id == util.hexstrdump(k.obj.getFingerprint()).toUpperCase()) {
				pubKey = k;
				break;
			}
		}
		if (pubKey == null) {
			res._oncomplete({ target: { result: null } });
			return res;
		}

		var pair = privKey.obj.privateKeyPacket.webCryptoPair;
		if (pair == null) {
			res._oncomplete({ target: { result: null } });
			return res;
		}
		var wpair = openpgp_webcrypto_pair2webcrypto_fetch(pair.keyId);
		if (wpair == null || wpair.webKeys['public'] == null) {
			res._oncomplete({ target: { result: null } });
			return res;
		}

		var resPair = new openpgp_keypair();
		resPair.id = id;
		resPair.privateKeyArmored = privKey.armored;
		resPair.publicKeyArmored = pubKey.armored;
		resPair.timePacket = openpgp_crypto_dateToTimePacket(
		    pubKey.obj.publicKeyPacket.creationTime);

		function exp_priv_done(r) {
			if (r.target.result == null) {
				res._oncomplete({ target: { result: null } });
				return;
			}
			resPair.privateKey = r.target.result;

			res._oncomplete({ target: { result: resPair } });
		}

		function exp_pub_done(r) {
			if (r.target.result == null) {
				res._oncomplete({ target: { result: null } });
				return;
			}
			resPair.publicKey = r.target.result;

			openpgp_webcrypto_get_key(wpair.webProvider,
			    wpair.webKeys['private'].name,
			    wpair.webKeys['private'].id).then(exp_priv_done,
			    pass_error);
		}

		function pass_error(e) {
			res._onerror(e);
		}

		openpgp_webcrypto_get_key(wpair.webProvider,
		    wpair.webKeys['public'].name,
		    wpair.webKeys['public'].id).then(exp_pub_done, pass_error);
		return res;
	}
	this.getWebCryptoPairById = getWebCryptoPairById;
	
	/**
	 * returns the openpgp_msg_privatekey representation of the public key at public key ring index  
	 * @param {Integer} index the index of the public key within the publicKeys array
	 * @return {openpgp_msg_privatekey} the public key object
	 */
	function exportPublicKey(index) {
		return this.publicKey[index];
	}
	this.exportPublicKey = exportPublicKey;
		
	
	/**
	 * Removes a public key from the public key keyring at the specified index 
	 * @param {Integer} index the index of the public key within the publicKeys array
	 * @return {openpgp_msg_privatekey} The public key object which has been removed
	 */
	function removePublicKey(index) {
		var removed = this.publicKeys.splice(index,1);
		this.store();
		return removed;
	}
	this.removePublicKey = removePublicKey;

	/**
	 * returns the openpgp_msg_privatekey representation of the private key at private key ring index  
	 * @param {Integer} index the index of the private key within the privateKeys array
	 * @return {openpgp_msg_privatekey} the private key object
	 */	
	function exportPrivateKey(index) {
		return this.privateKeys[index];
	}
	this.exportPrivateKey = exportPrivateKey;

	/**
	 * Removes a private key from the private key keyring at the specified index 
	 * @param {Integer} index the index of the private key within the privateKeys array
	 * @return {openpgp_msg_privatekey} The private key object which has been removed
	 */
	function removePrivateKey(index) {
		var removed = this.privateKeys.splice(index,1);
		this.store();
		return removed;
	}
	this.removePrivateKey = removePrivateKey;

}
