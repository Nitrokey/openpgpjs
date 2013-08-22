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

function openpgp_owncrypto_init(window)
{
	var that = {};

	that.crypto = {};
	that.subtle = {};

	that.crypto.getRandomValues = window.crypto.getRandomValues;

	that.subtle.generateKey = function (algo, flag, usage) {
		var res = new openpgp_promise();
		var numBits;

		switch (algo.name) {
		case 'RSASSA-PKCS1-v1_5':
		case 'RSAES-PKCS1-v1_5':
		      break;

		default:
		      res._onerror('owncrypto.generateKey: algorithm ' + algo.name + ' not supported yet');
		      return res;
		}

		openpgp_crypto_generateKeyPair_own(algo, ''/*passphrase*/, 0/*s2kHash*/, 0/*symmetricEncryptionAlgorithm*/).then(
			function (e) {
				res._oncomplete({ target: { result: e } });
			},
			function (e) {
				res._onerror({ target: { result: e } });
			}
		);
		return res;
	}

	that.subtle.exportKey = function (format, key) {
		var res = new openpgp_promise();
		openpgp_crypto_exportKey_own(format, key).then(
			function (e) {
				res._oncomplete({ target: { result: e } });
			},
			function (e) {
				res._onerror({ target: { result: e } });
			}
		);
		return res;
	}

	that.subtle.sign = function (algo, key, buffer) {
		var res = new openpgp_promise();
		openpgp_crypto_signData_own(algo, key, buffer).then(
			function (e) {
				res._oncomplete({ target: { result: e } });
			},
			function (e) {
				res._onerror(e)
			}
		);
		return res;
	}

	return that;
}

openpgp_webcrypto_provider_add('owncrypto', openpgp_owncrypto_init);
