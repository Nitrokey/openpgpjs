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

openpgp_der_types = {
	0:	"endOfContent",
	1:	"boolean",
	2:	"integer",
	3:	"bitString",
	4:	"octetString",
	5:	"null",
	6:	"objectIdentifier",
	7:	"objectDescriptor",
	8:	"external",
	9:	"real",
	10:	"enumerated",
	11:	"embeddedPDV",
	12:	"UTF8String",
	13:	"relativeOID",
	14:	"reserved14",
	15:	"reserved15",
	16:	"sequence",
	17:	"set",
	18:	"numericString",
	19:	"printableString",
	20:	"T61String",
	21:	"VideotexString",
	22:	"IA5String",
	23:	"UTCTime",
	24:	"generalizedTime",
	25:	"graphicString",
	26:	"visibleString",
	27:	"generalString",
	28:	"universalString",
	29:	"characterString",
	30:	"bmpString"
};

/* Also provide the inverse mapping. */
function openpgp_der_invert_types() {
	var k, inv = {};

	for (k in openpgp_der_types)
		inv[openpgp_der_types[k]] = k;
	for (k in inv)
		openpgp_der_types[k] = inv[k];
};
openpgp_der_invert_types();

function openpgp_encoding_der()
{
	this.size = null;
	this.bsize = null;
	this.bgrosssize = null;
	this.bheader = null;
	this.bcontent = null;
	this.type = null;
	this.value = null;

	this.t = openpgp_der_types;

	function parse(arr) {

		/* Validate the length first. */
		if (arr.length < 2)
			throw 'DER format error: at least two bytes required';
		objOffset = 2;
		if (arr[1] < 128) {
			objLen = arr[1];
		} else if (arr[1] == 128) {
			throw 'DER format error: indefinite length octet';
		} else {
			objLen = 0;
			while (objOffset < arr[1] - 128 + 2) {
				objLen = objLen * 256 + arr[objOffset];
				objOffset++;
			}
		}

		this.bgrosssize = objOffset + objLen;
		this.bheader = util.subarray(arr, 0, objOffset);
		this.bsize = objLen;
		this.bcontent = util.subarray(arr, objOffset, objOffset + objLen);

		this.type = arr[0] & (255 - 32);
		if (this.type == this.t["sequence"]) {
			var carr = util.subarray(this.bcontent, 0);
			var res = [];

			while (carr.length > 0) {
				var memb = new openpgp_encoding_der().parse(carr);
				res.push(memb);
				carr = util.subarray(carr, memb.bgrosssize, carr.length);
			}
			this.value = res;
		} else if (this.type == this.t["bitString"]) {
			if (this.bsize < 2)
				throw "Empty bit string";
			if (this.bcontent[0] != 0)
				throw "Bit strings with spare bits not supported yet";
			var carr = util.subarray(this.bcontent, 1);
			var res = new openpgp_encoding_der().parse(carr);
			if (res.bgrosssize != carr.length)
				throw "Bit string enveloped object size mismatch, expected " + carr.length + ", got " + res.bgrosssize;
			this.value = res;
		}

		return this;
	}

	this.parse = parse;
}
