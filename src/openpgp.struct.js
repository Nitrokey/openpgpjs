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

/**
 * @typedef {Object} openpgp_keypair
 * @property {WebCrypto.Key} privateKey 
 * @property {WebCrypto.Key} publicKey
 * @property {String} publicKeyArmored
 */

function openpgp_keypair()
{
	function fromRawPair(raw) {
		this.symmetricEncryptionAlgorithm = raw.symmetricEncryptionAlgorithm;
		this.timePacket = raw.timePacket;
		this.privateKey = raw.privateKey;
		this.publicKey = raw.publicKey;
		this.publicKeyArmored = null;
	}

	this.id = null;
	this.mainKeyId = null;
	this.symmetricEncryptionAlgorithm = null;
	this.timePacket = null;
	this.privateKey = null;
	this.publicKey = null;
	this.publicKeyArmored = null;
	this.privateKeyArmored = null;

	this.subKeys = {};

	this.fromRawPair = fromRawPair;
}

/**
 * @typedef {Object} openpgp_keypair_raw
 * @property {Integer} numBits
 * @property {Integer} symmetricEncryptionAlgorithm
 * @property {String} timePacket
 * @property {WebCrypto.Key} privateKey
 * @property {WebCrypto.Key} publicKey
 */

function openpgp_keypair_raw()
{
	this.numBits = null;
	this.symmetricEncryptionAlgorithm = null;
	this.timePacket = null;
	this.privateKey = null;
	this.publicKey = null;
}

function openpgp_webcrypto_provider()
{
	this.name = null;
	this.crypto = null;
	this.subtle = null;

	this.initFunc = null;
	this.initAttempted = false;
}

function openpgp_pair2webcrypto_subkey(_type, _name, _id)
{
	this.type = _type;
	this.name = _name;
	this.id = _id;
}

function openpgp_pair2webcrypto_subpair(_id, _provider, _mainKeyId)
{
	this.keyId = _id;
	this.mainKeyId = _mainKeyId != null? _mainKeyId: _id;
	this.webProvider = _provider;
	this.webKeys = {};
	this.subKeys = [];
}
