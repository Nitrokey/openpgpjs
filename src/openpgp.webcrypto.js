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

var openpgp_webcrypto = null;
var openpgp_webcrypto_subtle = null;

var openpgp_webcrypto_providers = {};
var openpgp_webcrypto_preferred_providers = [
	'browser',	/* native browser window.crypto.subtle support!	*/
	'nfwebcrypto',	/* Netflix's NfWebCrypto framework		*/
	'domcrypt',	/* Mozilla's domCrypt extension			*/
	'own'		/* OpenPGPjs's JavaScript PKI implementation	*/
];

function openpgp_webcrypto_provider_add(name, initfunc)
{
	openpgp_webcrypto_providers[name] = initfunc;
}

function openpgp_webcrypto_init(window, preferred)
{
	/* Make sure we have something... */
	if (preferred == null)
		preferred = openpgp_webcrypto_preferred_providers;

	/* Also accept a single provider name. */
	if (typeof preferred == 'string' || preferred instanceof String)
		preferred = [preferred];

	/* Well... go for it! */
	var res = null;
	for (var i = 0; i < preferred.length; i++) {
		var name = preferred[i];
		var initfunc = openpgp_webcrypto_providers[name];

		if (initfunc == null)
			continue;

		try {
			var r = initfunc(window);

			if (r == null || r.crypto == null || r.subtle == null)
				continue;

			/* Found it! */
			res = r;
			break;
		} catch (err) {
		}
	}

	if (res == null)
		throw 'openpgp_webcrypto_init(): could not find a suitable WebCrypto provider';

	openpgp_webcrypto = res.crypto;
	openpgp_webcrypto_subtle = res.subtle;
	return true;
}

function openpgp_browser_crypto_init(window)
{
	if (window.crypto == null || window.crypto.subtle == null)
		return null;
	return { crypto: window.crypto, subtle: window.crypto.subtle };
}

openpgp_webcrypto_provider_add('browser', openpgp_browser_crypto_init);
