/*-
 * Copyright (c) 2013  Peter Pentchev
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

function openpgp_cryptostick_init(window)
{
	if (window.cryptostick == null) {
		throw 'cryptostick.webcrypto extension not found, unable to create openpgp_cryptostick';
	}

	var that = {};

	that.crypto = window.cryptostick.crypto;
	that.subtle = {
		exportKey: window.cryptostick.crypto.subtle.exportKey,

		decrypt: window.cryptostick.crypto.subtle.decrypt,

		sign: function (algo, key, data) {
			var m = openpgp_encoding_emsa_pkcs1_encode_to_string(
			    8, util.bin2str(data), key.opgp.numBits / 8);
			var ua = util.str2bin(m);
			/* OK, let's try something crazy now... unpad! */
			if (ua[0] != 0 || ua[1] != 1) {
				var res = new openpgp_promise();

				res._onerror({ target: { result:
				    'OpenPGP.js CryptoStick internal error: ' +
				    'the EMSA-padded stuff did not start ' +
				    'with 00 01' } });
				return res;
			}
			for (var xx = 2; xx < ua.length; xx++)
				if (ua[xx] != 255)
					break;
			if (xx == ua.length || ua[xx] != 0) {
				var res = new openpgp_promise();

				res._onerror({ target: { result:
				    'OpenPGP.js CryptoStick internal error: ' +
				    'the EMSA-padded stuff did not have ' +
				    'the 00 marker and/or data' } });
				return res;
			}
			ua = util.subarray(ua, xx + 1);
			return window.cryptostick.crypto.subtle.sign(
			    algo, key, ua);
		}
	};
	that.cryptokeys = {
		getKeyByName: function (name) {
			var res = new openpgp_promise();

			window.cryptostick.cryptokeys.getKeyByName(name).then(
				function (r) {
					var arr = [];
					for (var i = 0; i < r.target.result.count(); i++) {
						var k = util.cloneChromeObject(r.target.result.get(i));
						openpgp_webcrypto_tag(k, k.cs_numBits, 'cryptostick');
						arr[arr.length] = k;
					}
					res._oncomplete({ target: { result: arr } });
				},
				function (e) {
					res._onerror(e);
				}
			);
			return res;
		}
	};
	that.opgp = {
		getMatchingPrivateKey: function (k, keys) {
			for (var i = 0; i < keys.length; i++)
				if (k.name == keys[i].name && i < keys.length - 1)
					return keys[i + 1];
			return null;
		}
	};
	return that;
}

openpgp_webcrypto_provider_add('cryptostick', openpgp_cryptostick_init);
