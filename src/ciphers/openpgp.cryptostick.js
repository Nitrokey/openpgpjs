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
	that.subtle = window.cryptostick.crypto.subtle;
	that.cryptokeys = {
		getKeyByName: function (name) {
			var res = new openpgp_promise();

			window.cryptostick.cryptokeys.getKeyByName(name).then(
				function (r) {
					console.log("RDBG hfff got result:"); console.log(r);
					console.log("RDBG hfff - count " + r.target.result.count());
					var arr = [];
					for (var i = 0; i < r.target.result.count(); i++) {
						console.log("RDBG   - " + i); console.log(r.target.result.get(i));
						arr[arr.length] = r.target.result.get(i);
					}
					console.log("RDBG hfff - returning stuff"); console.log(arr);
					res._oncomplete({ target: { result: arr } });
				},
				function (e) {
					res._onerror(e);
				}
			);
			return res;
		}
	};
	window.cryptostick.cryptokeys;
	return that;
}

openpgp_webcrypto_provider_add('cryptostick', openpgp_cryptostick_init);
