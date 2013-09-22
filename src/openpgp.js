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
 * @fileoverview The openpgp base class should provide all of the functionality 
 * to consume the openpgp.js library. All additional classes are documented 
 * for extending and developing on top of the base library.
 */

/**
 * GPG4Browsers Core interface. A single instance is hold
 * from the beginning. To use this library call "openpgp.init()"
 * @alias openpgp
 * @class
 * @classdesc Main Openpgp.js class. Use this to initiate and make all calls to this library.
 */
function _openpgp () {
	this.tostring = "";
	
	/**
	 * initializes the library:
	 * - reading the keyring from local storage
	 * - initializing the WebCrypto provider and support
	 * - reading the config from local storage
	 */
	function init(webcrypto_preferred) {
		this.config = new openpgp_config();
		this.config.read();

		openpgp_webcrypto_init(window, webcrypto_preferred);

		this.keyring = new openpgp_keyring();
		this.keyring.init();
	}
	
	/**
	 * reads several publicKey objects from a ascii armored
	 * representation an returns openpgp_msg_publickey packets
	 * @param {String} armoredText OpenPGP armored text containing
	 * the public key(s)
	 * @return {openpgp_msg_publickey[]} on error the function
	 * returns null
	 */
	function read_publicKey(armoredText) {
		var mypos = 0;
		var publicKeys = new Array();
		var publicKeyCount = 0;
		var input = openpgp_encoding_deArmor(armoredText.replace(/\r/g,'')).openpgp;
		var l = input.length;
		while (mypos != input.length) {
			var first_packet = openpgp_packet.read_packet(input, mypos, l);
			// public key parser
			if (input[mypos].charCodeAt() == 0x99 || first_packet.tagType == 6) {
				publicKeys[publicKeyCount] = new openpgp_msg_publickey();				
				publicKeys[publicKeyCount].header = input.substring(mypos,mypos+3);
				if (input[mypos].charCodeAt() == 0x99) {
					// parse the length and read a tag6 packet
					mypos++;
					var l = (input[mypos++].charCodeAt() << 8)
							| input[mypos++].charCodeAt();
					publicKeys[publicKeyCount].publicKeyPacket = new openpgp_packet_keymaterial();
					publicKeys[publicKeyCount].publicKeyPacket.header = publicKeys[publicKeyCount].header;
					publicKeys[publicKeyCount].publicKeyPacket.read_tag6(input, mypos, l);
					mypos += publicKeys[publicKeyCount].publicKeyPacket.packetLength;
					mypos += publicKeys[publicKeyCount].read_nodes(publicKeys[publicKeyCount].publicKeyPacket, input, mypos, (input.length - mypos));
				} else {
					publicKeys[publicKeyCount] = new openpgp_msg_publickey();
					publicKeys[publicKeyCount].publicKeyPacket = first_packet;
					mypos += first_packet.headerLength+first_packet.packetLength;
					mypos += publicKeys[publicKeyCount].read_nodes(first_packet, input, mypos, input.length -mypos);
				}
			} else {
				util.print_error("no public key found!");
				return null;
			}
			publicKeys[publicKeyCount].data = input.substring(0,mypos);
			publicKeyCount++;
		}
		return publicKeys;
	}
	
	/**
	 * reads several privateKey objects from a ascii armored
	 * representation an returns openpgp_msg_privatekey objects
	 * @param {String} armoredText OpenPGP armored text containing
	 * the private key(s)
	 * @return {openpgp_msg_privatekey[]} on error the function
	 * returns null
	 */
	function read_privateKey(armoredText) {
		var privateKeys = new Array();
		var privateKeyCount = 0;
		var mypos = 0;
		var input = openpgp_encoding_deArmor(armoredText.replace(/\r/g,'')).openpgp;
		var l = input.length;
		while (mypos != input.length) {
			var first_packet = openpgp_packet.read_packet(input, mypos, l);
			if (first_packet.tagType == 5) {
				privateKeys[privateKeys.length] = new openpgp_msg_privatekey();
				mypos += first_packet.headerLength+first_packet.packetLength;
				mypos += privateKeys[privateKeyCount].read_nodes(first_packet, input, mypos, l);
			// other blocks	            
			} else {
				util.print_error('no block packet found!');
				return null;
			}
			privateKeys[privateKeyCount].data = input.substring(0,mypos);
			privateKeyCount++;
		}
		return privateKeys;		
	}

	/**
	 * reads message packets out of an OpenPGP armored text and
	 * returns an array of message objects
	 * @param {String} armoredText text to be parsed
	 * @return {openpgp_msg_message[]} on error the function
	 * returns null
	 */
	function read_message(armoredText) {
		var dearmored;
		try{
    		dearmored = openpgp_encoding_deArmor(armoredText.replace(/\r/g,''));
		}
		catch(e){
    		util.print_error('no message found!');
    		return null;
		}
		return read_messages_dearmored(dearmored);
		}
		
	/**
	 * reads message packets out of an OpenPGP armored text and
	 * returns an array of message objects. Can be called externally or internally.
	 * External call will parse a de-armored messaged and return messages found.
	 * Internal will be called to read packets wrapped in other packets (i.e. compressed)
	 * @param {String} input dearmored text of OpenPGP packets, to be parsed
	 * @return {openpgp_msg_message[]} on error the function
	 * returns null
	 */
	function read_messages_dearmored(input){
		var messageString = input.openpgp;
		var signatureText = input.text; //text to verify signatures against. Modified by Tag11.
		var messages = new Array();
		var messageCount = 0;
		var mypos = 0;
		var l = messageString.length;
		while (mypos < messageString.length) {
			var first_packet = openpgp_packet.read_packet(messageString, mypos, l);
			if (!first_packet) {
				break;
			}
			// public key parser (definition from the standard:)
			// OpenPGP Message      :- Encrypted Message | Signed Message |
			//                         Compressed Message | Literal Message.
			// Compressed Message   :- Compressed Data Packet.
			// 
			// Literal Message      :- Literal Data Packet.
			// 
			// ESK                  :- Public-Key Encrypted Session Key Packet |
			//                         Symmetric-Key Encrypted Session Key Packet.
			// 
			// ESK Sequence         :- ESK | ESK Sequence, ESK.
			// 
			// Encrypted Data       :- Symmetrically Encrypted Data Packet |
			//                         Symmetrically Encrypted Integrity Protected Data Packet
			// 
			// Encrypted Message    :- Encrypted Data | ESK Sequence, Encrypted Data.
			// 
			// One-Pass Signed Message :- One-Pass Signature Packet,
			//                         OpenPGP Message, Corresponding Signature Packet.

			// Signed Message       :- Signature Packet, OpenPGP Message |
			//                         One-Pass Signed Message.
			if (first_packet.tagType ==  1 ||
			    (first_packet.tagType == 2 && first_packet.signatureType < 16) ||
			     first_packet.tagType ==  3 ||
			     first_packet.tagType ==  4 ||
				 first_packet.tagType ==  8 ||
				 first_packet.tagType ==  9 ||
				 first_packet.tagType == 10 ||
				 first_packet.tagType == 11 ||
				 first_packet.tagType == 18 ||
				 first_packet.tagType == 19) {
				messages[messages.length] = new openpgp_msg_message();
				messages[messageCount].messagePacket = first_packet;
				messages[messageCount].type = input.type;
				// Encrypted Message
				if (first_packet.tagType == 9 ||
				    first_packet.tagType == 1 ||
				    first_packet.tagType == 3 ||
				    first_packet.tagType == 18) {
					if (first_packet.tagType == 9) {
						util.print_error("unexpected openpgp packet");
						break;
					} else if (first_packet.tagType == 1) {
						util.print_debug("session key found:\n "+first_packet.toString());
						var issessionkey = true;
						messages[messageCount].sessionKeys = new Array();
						var sessionKeyCount = 0;
						while (issessionkey) {
							messages[messageCount].sessionKeys[sessionKeyCount] = first_packet;
							mypos += first_packet.packetLength + first_packet.headerLength;
							l -= (first_packet.packetLength + first_packet.headerLength);
							first_packet = openpgp_packet.read_packet(messageString, mypos, l);
							
							if (first_packet.tagType != 1 && first_packet.tagType != 3)
								issessionkey = false;
							sessionKeyCount++;
						}
						if (first_packet.tagType == 18 || first_packet.tagType == 9) {
							util.print_debug("encrypted data found:\n "+first_packet.toString());
							messages[messageCount].encryptedData = first_packet;
							mypos += first_packet.packetLength+first_packet.headerLength;
							l -= (first_packet.packetLength+first_packet.headerLength);
							messageCount++;
							
						} else {
							util.print_debug("something is wrong: "+first_packet.tagType);
						}
						
					} else if (first_packet.tagType == 18) {
						util.print_debug("symmetric encrypted data");
						break;
					}
				} else 
					if (first_packet.tagType == 2 && first_packet.signatureType < 3) {
					// Signed Message
						mypos += first_packet.packetLength + first_packet.headerLength;
						l -= (first_packet.packetLength + first_packet.headerLength);
						messages[messageCount].text = signatureText;
						messages[messageCount].signature = first_packet;
				        messageCount++;
				} else 
					// Signed Message
					if (first_packet.tagType == 4) {
						//TODO: Implement check
						mypos += first_packet.packetLength + first_packet.headerLength;
						l -= (first_packet.packetLength + first_packet.headerLength);
				} else 
					if (first_packet.tagType == 8) {
					// Compressed Message
						mypos += first_packet.packetLength + first_packet.headerLength;
						l -= (first_packet.packetLength + first_packet.headerLength);
				        var decompressedText = first_packet.decompress();
				        messages = messages.concat(openpgp.read_messages_dearmored({text: decompressedText, openpgp: decompressedText}));
				} else
					// Marker Packet (Obsolete Literal Packet) (Tag 10)
					// "Such a packet MUST be ignored when received." see http://tools.ietf.org/html/rfc4880#section-5.8
					if (first_packet.tagType == 10) {
						// reset messages
						messages.length = 0;
						// continue with next packet
						mypos += first_packet.packetLength + first_packet.headerLength;
						l -= (first_packet.packetLength + first_packet.headerLength);
				} else 
					if (first_packet.tagType == 11) {
					// Literal Message -- work is already done in read_packet
					mypos += first_packet.packetLength + first_packet.headerLength;
					l -= (first_packet.packetLength + first_packet.headerLength);
					signatureText = first_packet.data;
					messages[messageCount].data = first_packet.data;
					messageCount++;
				} else 
					if (first_packet.tagType == 19) {
					// Modification Detect Code
						mypos += first_packet.packetLength + first_packet.headerLength;
						l -= (first_packet.packetLength + first_packet.headerLength);
				}
			} else {
				util.print_error('no message found!');
				return null;
			}
		}
		
		return messages;
	}
	
	/**
	 * creates a binary string representation of an encrypted and signed message.
	 * The message will be encrypted with the public keys specified and signed
	 * with the specified private key.
	 * @param {Object} privatekey {obj: [openpgp_msg_privatekey]} Private key 
	 * to be used to sign the message
	 * @param {Object[]} publickeys An arraf of {obj: [openpgp_msg_publickey]}
	 * - public keys to be used to encrypt the message 
	 * @param {String} messagetext message text to encrypt and sign
	 * @return {String} a binary string representation of the message which 
	 * can be OpenPGP armored
	 */
	function write_signed_and_encrypted_message(privatekey, publickeys, messagetext) {
		var result = "";
		var literal = new openpgp_packet_literaldata().write_packet(messagetext.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n"));
		util.print_debug_hexstr_dump("literal_packet: |"+literal+"|\n",literal);
		for (var i = 0; i < publickeys.length; i++) {
			var onepasssignature = new openpgp_packet_onepasssignature();
			var onepasssigstr = "";
			if (i == 0)
				onepasssigstr = onepasssignature.write_packet(1, openpgp.config.config.prefer_hash_algorithm,  privatekey, false);
			else
				onepasssigstr = onepasssignature.write_packet(1, openpgp.config.config.prefer_hash_algorithm,  privatekey, false);
			util.print_debug_hexstr_dump("onepasssigstr: |"+onepasssigstr+"|\n",onepasssigstr);
			var datasignature = new openpgp_packet_signature().write_message_signature(1, messagetext.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n"), privatekey);
			util.print_debug_hexstr_dump("datasignature: |"+datasignature.openpgp+"|\n",datasignature.openpgp);
			if (i == 0) {
				result = onepasssigstr+literal+datasignature.openpgp;
			} else {
				result = onepasssigstr+result+datasignature.openpgp;
			}
		}
		
		util.print_debug_hexstr_dump("signed packet: |"+result+"|\n",result);
		// signatures done.. now encryption
		var sessionkey = openpgp_crypto_generateSessionKey(openpgp.config.config.encryption_cipher); 
		var result2 = "";
		
		// creating session keys for each recipient
		for (var i = 0; i < publickeys.length; i++) {
			var pkey = publickeys[i].getEncryptionKey();
			if (pkey == null) {
				util.print_error("no encryption key found! Key is for signing only.");
				return null;
			}
			result2 += new openpgp_packet_encryptedsessionkey().
					write_pub_key_packet(
						pkey.getKeyId(),
						pkey.MPIs,
						pkey.publicKeyAlgorithm,
						openpgp.config.config.encryption_cipher,
						sessionkey);
		}
		if (openpgp.config.config.integrity_protect) {
			result2 += new openpgp_packet_encryptedintegrityprotecteddata().write_packet(openpgp.config.config.encryption_cipher, sessionkey, result);
		} else {
			result2 += new openpgp_packet_encrypteddata().write_packet(openpgp.config.config.encryption_cipher, sessionkey, result);
		}
		return openpgp_encoding_armor(3,result2,null,null);
	}
	/**
	 * creates a binary string representation of an encrypted message.
	 * The message will be encrypted with the public keys specified 
	 * @param {Object[]} publickeys An array of {obj: [openpgp_msg_publickey]}
	 * -public keys to be used to encrypt the message 
	 * @param {String} messagetext message text to encrypt
	 * @return {String} a binary string representation of the message
	 * which can be OpenPGP armored
	 */
	function write_encrypted_message(publickeys, messagetext) {
		var result = "";
		var literal = new openpgp_packet_literaldata().write_packet(messagetext.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n"));
		util.print_debug_hexstr_dump("literal_packet: |"+literal+"|\n",literal);
		result = literal;
		
		// signatures done.. now encryption
		var sessionkey = openpgp_crypto_generateSessionKey(openpgp.config.config.encryption_cipher); 
		var result2 = "";
		
		// creating session keys for each recipient
		for (var i = 0; i < publickeys.length; i++) {
			var pkey = publickeys[i].getEncryptionKey();
			if (pkey == null) {
				util.print_error("no encryption key found! Key is for signing only.");
				return null;
			}
			result2 += new openpgp_packet_encryptedsessionkey().
					write_pub_key_packet(
						pkey.getKeyId(),
						pkey.MPIs,
						pkey.publicKeyAlgorithm,
						openpgp.config.config.encryption_cipher,
						sessionkey);
		}
		if (openpgp.config.config.integrity_protect) {
			result2 += new openpgp_packet_encryptedintegrityprotecteddata().write_packet(openpgp.config.config.encryption_cipher, sessionkey, result);
		} else {
			result2 += new openpgp_packet_encrypteddata().write_packet(openpgp.config.config.encryption_cipher, sessionkey, result);
		}
		return openpgp_encoding_armor(3,result2,null,null);
	}
	
	/**
	 * creates a binary string representation a signed message.
	 * The message will be signed with the specified private key.
	 * @param {WebCrypto Key} privatekey
	 * - the private key to be used to sign the message 
	 * @param {String} publicKey
	 * - the armored public key to be used to sign the message
	 * @param {String} messagetext message text to sign
	 * @return {Object} {Object: text [String]}, openpgp: {String} a binary
	 *  string representation of the message which can be OpenPGP
	 *   armored(openpgp) and a text representation of the message (text). 
	 * This can be directly used to OpenPGP armor the message
	 */
	function write_signed_message(privatekey, publickey, messagetext) {
		var res = new openpgp_promise();
		var sanitized = messagetext.replace(/\r\n/g,"\n").replace(/\n/,"\r\n");
		
		function pass_error(e) {
			res._onerror(e);
		}

		function sign_complete(sig) {
			var result = {text: sanitized, openpgp: sig.openpgp, hash: sig.hash};
			res._oncomplete(openpgp_encoding_armor(2,result, null, null));
		}

		var publicKeyMat = null;
		if (typeof(publickey) == "string" || publickey instanceof String)
		{
			var pk = openpgp_encoding_deArmor(publickey).openpgp;
			publicKeyMat = new openpgp_packet.read_packet(pk, 0, pk.length);
		} else {
			throw 'FIXME: support WebCrypto Key objects directly here';
		}
		var signature = new openpgp_packet_signature();
		signature.write_message_signature(1, sanitized, privatekey, publicKeyMat).
		    then(sign_complete, pass_error);
		return res;
	}
	
	function verify_armored_message(data)
	{
		var res = new openpgp_promise();

		if (data.substring(0, 11) == "-----BEGIN ") {
			data = openpgp_encoding_deArmor(data);
			if (!data) {
				res._onerror({ target: { result:
				    'Could not dearmor the OpenPGP message'
				} });
				return res;
			}
		}
		var packets = read_messages_dearmored(data);
		if (packets == null || packets.length == 0) {
			res._onerror({ target: { result:
			    'Could not read OpenPGP message packets' } });
			return res;
		} else if (packets[0].verifySignature == null) {
			res._onerror({ target: { result:
			    'Not an OpenPGP signed message' } });
			return res;
		}
		return packets[0].verifySignature();
	}
	this.verify_armored_message = verify_armored_message;

	/**
	 * Extract a RSA keypair from a SPKI DER sequence.
	 */
	function openpgp_spki_to_rsa(der)
	{
		var wrap = new openpgp_encoding_der().parse(der);
		if (wrap.bgrosssize != der.length)
			throw "The DER object did not encompass the full array, expected " + der.length + " bytes, only got " + wrap.bgrosssize;

		if (wrap.type != wrap.t["sequence"] ||
		    wrap.value[0].type != wrap.t["sequence"] ||
		    wrap.value[0].value[0].type != wrap.t["objectIdentifier"] ||
		    wrap.value[1].type != wrap.t["bitString"] ||
		    wrap.value[1].value.type != wrap.t["sequence"] ||
		    wrap.value[1].value.value.length != 2 ||
		    wrap.value[1].value.value[0].type != wrap.t["integer"] ||
		    wrap.value[1].value.value[1].type != wrap.t["integer"])
			throw "Unexpected formatting of the SPKI DER keypair";

		var res = {
			key: wrap.value[1].value.value[0].bcontent,
			exp: wrap.value[1].value.value[1].bcontent
		};
		return res;
	}
	this.openpgp_spki_to_rsa = openpgp_spki_to_rsa;

	/**
	 * Extract a RSA keypair from a PKCS#8 DER sequence.
	 */
	function openpgp_pkcs8_to_rsa(der)
	{
		var wrap = new openpgp_encoding_der().parse(der);
		if (wrap.bgrosssize != der.length)
			throw "The DER object did not encompass the full array, expected " + der.length + " bytes, only got " + wrap.bgrosssize;

		if (wrap.type != wrap.t["sequence"] ||
		    wrap.length < 3 ||
		    wrap.value[0].type != wrap.t["integer"] ||
		    wrap.value[0].bcontent[0] != 0 ||
		    wrap.value[1].type != wrap.t["sequence"] ||
		    wrap.value[1].value.length < 1 ||
		    wrap.value[1].value[0].type != wrap.t["objectIdentifier"] ||
		    wrap.value[2].type != wrap.t["octetString"])
			throw "Unexpected formatting of the PKCS#8 DER key";
		var wrap2 = new openpgp_encoding_der().parse(wrap.value[2].bcontent);
		if (wrap2.type != wrap2.t["sequence"] ||
		    wrap2.length < 9 ||
		    wrap2.value[0].type != wrap.t["integer"] ||
		    wrap2.value[0].bcontent[0] != 0)
			throw "Unexpected formatting of the BER RSA key within the PKCS#8 DER key";
		for (var i = 1; i < 9; i++)
			if (wrap2.value[i].type != wrap2.t["integer"])
				throw "Unexpected formatting of integer " + i + " within the BER RSA key within the PKCS#8 DER key";

		var res = {
			n:	wrap2.value[1].bcontent,
			e:	wrap2.value[2].bcontent,
			d:	wrap2.value[3].bcontent,
			p:	wrap2.value[4].bcontent,
			q:	wrap2.value[5].bcontent,
			dmp1:	wrap2.value[6].bcontent,
			dmq1:	wrap2.value[7].bcontent,
			u:	wrap2.value[8].bcontent
		};
		return res;
	}

	/**
	 * generates a new key pair for openpgp. Beta stage. Currently only 
	 * supports RSA keys, and no subkeys.
	 * @param {Integer} keyType to indicate what type of key to make. 
	 * RSA is 1. Follows algorithms outlined in OpenPGP.
	 * @param {Integer} numBits number of bits for the key creation. (should 
	 * be 1024+, generally)
	 * @param {String} userId assumes already in form of "User Name 
	 * <username@email.com>"
	 * @param {String} passphrase The passphrase used to encrypt the resulting private key
	 * @return {Object} {privateKey: [openpgp_msg_privatekey], 
	 * privateKeyArmored: [string], publicKeyArmored: [string]}
	 */
	function generate_key_pair(keyType, numBits, userId, passphrase){
		var res = new openpgp_promise();

		var userIdPacket = new openpgp_packet_userid();
		var userIdString = userIdPacket.write_packet(userId);
		
		var keyPair = null, privKey = null, pubKey = null;
		var publicKeyString = null, publicKeyStringFull = null, publicKeyMat = null;
		var publicRSAKey;
		var privateKeyString = null, privateKeyStringFull = null;
		var result = new openpgp_keypair();

		pass_error = function (e) {
			res._onerror(e);
		}

		sign_oncomplete = function (sig) {
			keyPair.publicKeyArmored = openpgp_encoding_armor(4, publicKeyStringFull + userIdString + sig.openpgp );
			keyPair.privateKeyArmored = openpgp_encoding_armor(5, privateKeyStringFull + userIdString + sig.openpgp );

			res._oncomplete(keyPair);
		}

		exp_priv_private_key_written = function (pk) {
			privateKeyString = pk.body;
			privateKeyStringFull = pk.string;

			userId = util.encode_utf8(userId); // needs same encoding as in userIdString
			var hashData = String.fromCharCode(0x99)+ String.fromCharCode(((publicKeyString.length) >> 8) & 0xFF) 
				+ String.fromCharCode((publicKeyString.length) & 0xFF) +publicKeyString+String.fromCharCode(0xB4) +
				String.fromCharCode((userId.length) >> 24) +String.fromCharCode(((userId.length) >> 16) & 0xFF) 
				+ String.fromCharCode(((userId.length) >> 8) & 0xFF) + String.fromCharCode((userId.length) & 0xFF) + userId;
			var signature = new openpgp_packet_signature();
			signature.write_message_signature(16,hashData, privKey, publicKeyMat).then(sign_oncomplete, pass_error);
		}

		exp_priv_oncomplete = function (exp) {
			try {
				if (privKey.extractable) {
					if (exp == null) {
						res._onerror('Could not export the private key');
						return res;
					}
					var rsa = openpgp_pkcs8_to_rsa(exp);
					var rsaObj = new RSA();
					var rsaKey = new rsaObj.keyObject();
					for (var k in rsa) {
						if (!rsa.hasOwnProperty(k))
							continue;
						var str = util.hexidump(rsa[k]);
						var mpi = new BigInteger(str, 16);
						if (k != "e")
							rsaKey[k] = mpi;
						else
							rsaKey["ee"] = mpi;
					}

					exp_priv_private_key_written(
					    new openpgp_packet_keymaterial().write_private_key(
					    keyType, rsaKey, 'just', 8, 3, keyPair.timePacket));
				} else if (privKey.name != null) {
					new openpgp_packet_keymaterial().write_private_key_webcrypto_stub(
					    keyType, publicRSAKey, privKey, keyPair.timePacket).then(
					    exp_priv_private_key_written,
					    pass_error);
				}
			} catch (err) {
				console.log(err.stack);
				res._onerror("openpgp.generate_key_pair.exp_priv_oncomplete: exception caught: " + err);
			}
		}

		exp_pub_oncomplete = function (exp) {
			try {
				var rsa = openpgp_spki_to_rsa(exp);
				var keyStr = util.hexidump(rsa.key), expStr = util.hexidump(rsa.exp);
				var rsaObj = new RSA();
				publicRSAKey = new rsaObj.keyObject();
				publicRSAKey.n = new BigInteger(keyStr, 16);
				publicRSAKey.ee = new BigInteger(expStr, 16);
				var pk = new openpgp_packet_keymaterial().write_public_key(keyType, publicRSAKey, keyPair.timePacket);
				publicKeyString = pk.body;
				publicKeyStringFull = pk.string;
				publicKeyMat = new openpgp_packet_keymaterial().read_pub_key(publicKeyString, 0, publicKeyString.length);
				keyPair.id = util.hexstrdump(publicKeyMat.getFingerprint());
				openpgp_webcrypto_pair2webcrypto_store(keyPair);

				if (privKey.extractable)
					openpgp_crypto_exportKey("pkcs8", privKey).then(exp_priv_oncomplete, pass_error);
				else
					exp_priv_oncomplete(null);
			} catch (err) {
				res._onerror("openpgp.generate_key_pair.exp_pub_oncomplete: exception caught: " + err);
				console.log(err.stack);
			}
		}

		gen_oncomplete = function (pair) {
			try {
				keyPair = new openpgp_keypair();
				keyPair.fromRawPair(pair);
				privKey = pair.privateKey;
				pubKey = pair.publicKey;

				if (!pubKey.extractable) {
					res._onerror("openpgp.generate_key_pair(): WebCrypto generated a non-exportable public key " + pubKey);
					return;
				}
				openpgp_crypto_exportKey("spki", pubKey).then(exp_pub_oncomplete, pass_error);
			} catch (err) {
				// FIXME: we don't really need this level of detail
				res._onerror("openpgp.generate_keypair.gen_oncomplete: exception caught: " + err);
			}
		}

		openpgp_crypto_generateKeyPair(keyType,numBits, openpgp.config.config.prefer_hash_algorithm).then(gen_oncomplete, pass_error);
		return res;
	}
	
	this.generate_key_pair = generate_key_pair;
	this.write_signed_message = write_signed_message; 
	this.write_signed_and_encrypted_message = write_signed_and_encrypted_message;
	this.write_encrypted_message = write_encrypted_message;
	this.read_message = read_message;
	this.read_messages_dearmored = read_messages_dearmored;
	this.read_publicKey = read_publicKey;
	this.read_privateKey = read_privateKey;
	this.init = init;
}

var openpgp = new _openpgp();


