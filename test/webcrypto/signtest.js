var openpgp_initialized = false;
var generatedKeypair = null;
var submitButton = 'none';

function initialize_openpgp(provlist)
{
	if (openpgp_initialized)
		return true;

	if (provlist == null)
		//provlist = ["cryptostick", "domcrypt", "nfwebcrypto", "owncrypto"];
		provlist = ["cryptostick", "owncrypto"];
	window.alert("Initializing OpenPGPjs...");
	openpgp.init(provlist);
	openpgp_initialized = true;
}

function dogenkey()
{
	try {
		if (submitButton == 'fetch') {
			return dofetchkey();
		} else if (submitButton != 'gen') {
			window.alert('Internal error: submitButton is set to an unexpected value "' + submitButton + '" instead of "gen"');
			return false;
		}
		initialize_openpgp();

		openpgp.generate_key_pair(1, 1024, "roam@openpgp.ringlet.net", "passstuff").then(
			function (pair) {
				generatedKeypair = pair;
				$('textarea#genkeypub').val(pair.publicKeyArmored);
				if (pair.privateKeyArmored != null)
					$('textarea#genkeypriv').val(pair.privateKeyArmored);
				else
					$('textarea#genkeypriv').val('Private key not extractable');
				openpgp.keyring.importWebCryptoKeyPair(pair);
				openpgp.keyring.store();
			},
			function (e) {
				window.alert("dogenkey: openpgp.generate_key_pair() failed: " + e);
			}
		);
	} catch (err) {
		console.log(err);
		console.log(err.stack);
		window.alert("dogenkey() error: " + err);
	}
	return false;
}

function dolistkeys()
{
	try {
		initialize_openpgp();

		var prov = $('input[name=listprov]:checked', '#listkeysform').val();
		var all = $('input[name=listall]:checked', '#listkeysform').val();
		var name = $('#listname').val();
		var id = $('#listid').val();
		if (id == "")
			id = null;

		function show_keys_clear() {
			$('textarea#listkeysdata').val('');
		}

		function show_keys_start(num) {
			$('textarea#listkeysdata').val('Found ' + num + ' key' + (num == 1? "": "s") + "\n");
		}

		function show_single_key(k) {
			var s = "Key name " + k.name + " id " + k.id + "\n" +
			    "- algorithm " + k.algorithm.name + "\n" +
			    "- type " + k.type + "\n" +
			    "- extractable " + k.extractable + "\n" +
			    "- keyUsage " + k.keyUsage.join(", ") + "\n" +
			    "- cs_pkcs11id " + k.cs_pkcs11id + "\n" +
			    "\n";
			$('textarea#listkeysdata').val($('textarea#listkeysdata').val() + s);
		}

		function show_all_keys(k) {
			for (var i = 0; i < k.length; i++)
				show_single_key(k[i]);
		}

		function show_keys_end() {
		}

		show_keys_clear();
		if (all == "all") {
			openpgp_webcrypto_get_all_keys(prov).then(
				function (r) {
					var keys = r.target.result;
					show_keys_start(keys.length);
					show_all_keys(keys);
					show_keys_end();
				},
				function (e) {
					window.alert('Could not fetch all the keys for provider ' + prov + ': ' + e.target.result);
				}
			);
		} else {
			openpgp_webcrypto_get_key(prov, name, id).then(
				function (r) {
					if (r.target.result == null) {
						show_keys_start(0);
						return;
					}
					show_keys_start(1);
					show_single_key(r.target.result);
					show_keys_end();
				},
				function (e) {
					window.alert('Could not fetch key ' + name + ' / ' + id + ' for provider ' + prov + ': ' + e.target.result);
				}
			);
		}
	} catch (err) {
		console.log(err);
		console.log(err.stack);
		window.alert("dolistkeys() error: " + err);
	}
	return false;
}

function dofetchkey()
{
	try {
		if (submitButton != 'fetch') {
			window.alert('Internal error: submitButton is set to an unexpected value "' + submitButton + '" instead of "fetch"');
			return false;
		}
		initialize_openpgp();

		/* OK, do we have any private keys?  Any at all? */
		if (!openpgp.keyring.hasPrivateKey()) {
			window.alert("No private keys in the keyring!");
			return false;
		}

		var i = 0, idx;
		var k;

		function nextKey() {
			idx = i;
			if (idx == openpgp.keyring.privateKeys.length) {
				window.alert("No suitable private keys found!");
				return;
			}

			i++;
			try {
				k = openpgp.keyring.privateKeys[idx];
				var pair = k.obj.privateKeyPacket.webCryptoPair;
				if (pair == null) {
					if (k.obj.privateKeyPacket.MPIs != null) {
						/* Oh, we have this key fully! */
						/* ...but can't handle it yet... */
						window.alert('FIXME: import a "normal" PGP key using the owncrypto provider');
					}
					/* Nah, nowhere to fetch it from */
					nextKey();
					return;
				}

				openpgp_webcrypto_get_key(pair.webProvider, pair.webKeys['private'].name, pair.webKeys['private'].id).then(gotKey, gotError);
			} catch (err) {
				console.log("Error processing private key " + idx + ": " + err);
			}
		}

		function gotError(e) {
			console.log("Could not fetch private key " + idx + ": " + e.target.result);
			nextKey();
		}

		function gotKey(r) {
			if (r.target.result == null) {
				console.log("Could not fetch private key " + idx);
				nextKey();
			} else {
				foundKey(r.target.result);
			}
		}

		function foundKey(key) {
			console.log("RDBG found a key!"); console.log(key);
			console.log("RDBG for the PGP keyring key:"); console.log(k);
			window.alert("FIXME handle a found key :)");
		}

		nextKey();
	} catch (err) {
		console.log(err.stack);
		window.alert("dofetchkey() error: " + err);
	}
	return false;
}

function dosign()
{
	try {
		window.alert("dosign() starting");
		if (generatedKeypair == null) {
			window.alert("Please generate a key first");
			return false;
		}
		initialize_openpgp();

		function sign_error(e) {
			window.alert("Signing error: " + e);
		}

		function sign_complete(r) {
			$('textarea#signsigned').val(r);
		}

		openpgp.write_signed_message(generatedKeypair.privateKey, generatedKeypair.publicKeyArmored, $('textarea#signplain').val()).then(sign_complete, sign_error);
	} catch (err) {
		console.log(err.toString()); console.log(err); console.log(err.stack);
		window.alert("dosign() error: " + err);
	}
	return false;
}

function doimportpub()
{
	try {
		initialize_openpgp();

		var prov = $('input[name=listprov]:checked', '#listkeysform').val();
		var pubarmored = $('textarea#importkeypub').val();

		var pk;
		try {
			pk = openpgp.read_publicKey(pubarmored);
			if (pk == null)
				throw 'No public key at all';
		} catch (err) {
			console.log(err.toString()); console.log(err); console.log(err.stack);
			window.alert("Please paste a valid public key into the text area below");
			return false;
		}
		console.log("RDBG got a public key:"); console.log(pk);
		console.log("RDBG data.len: " + pk[0].data.length);
		console.log("RDBG publicKeyPacket.data.len: " + pk[0].publicKeyPacket.data.length);

		openpgp_webcrypto_matchKey(prov, pk).then(
			function (r) {
				try {
					var pair = r.target.result;

					console.log("RDBG got a WebCrypto pair:"); console.log(pair);
					/* No need for this for the present, I think.
					var existing = openpgp_webcrypto_pair2webcrypto_fetch(pair.id);
					if (existing != null) {
						window.alert("This key is already known to OpenPGP.js from provider " + existing.webProvider);
						return;
					}
					*/
					openpgp_webcrypto_pair2webcrypto_store(pair);

					for (i = 0; i < openpgp.keyring.publicKeys.length; i++) {
						var fp = util.hexstrdump(
						    openpgp.keyring.publicKeys[i].obj.getFingerprint());
						if (fp != pair.id)
							continue;
						console.log("About to remove public key " + fp + " (position " + i + ") from the keyring");
						openpgp.keyring.removePublicKey(i);
						i--;
					}
					for (i = 0; i < openpgp.keyring.privateKeys.length; i++) {
						var fp = util.hexstrdump(
						    openpgp.keyring.privateKeys[i].obj.getFingerprint());
						if (fp != pair.id)
							continue;
						console.log("About to remove private key " + fp + " (position " + i + ") from the keyring");
						openpgp.keyring.removePrivateKey(i);
						i--;
					}
					openpgp.keyring.importWebCryptoKeyPair(pair).then(
						function (r) {
							window.alert("Key imported!");
						},
						function (e) {
							window.alert(e.target.result);
						}
					);
					openpgp.keyring.store();
				} catch (err) {
					console.log(err.toString()); console.log(err); console.log(err.stack);
					window.alert("Error processing the keypair: " + err);
				}
			},

			function (e) {
				window.alert("This key does not seem to be provisioned by " + prov + ": " + e.target.result);
			}
		);
	} catch (err) {
		console.log(err);
		console.log(err.stack);
		window.alert("doimportpub() error: " + err);
	}
	return false;
}

function dokeyring_weball()
{
	try {
		initialize_openpgp();

		var arr = openpgp_webcrypto_pair2webcrypto_fetch_all();
		s = "";
		for (var name in arr) {
			var wpair = arr[name];

			s += "WebCrypto pair " + name + ": provider " + wpair.webProvider +
			    " id " + wpair.keyId + "\n";
			for (var ktype in wpair.webKeys) {
				var wk = wpair.webKeys[ktype];
				s += "- " + ktype + ": type " + wk.type +
				    " name " + wk.name +
				    " id " + wk.id +
				    "\n";
			}
			s += "\n";
		}

		$('textarea#keyringkeys').val(s);
	} catch (err) {
		console.log(err.toString()); console.log(err); console.log(err.stack);
		window.alert("dokeyring_weball() error: " + err);
	}
	return false;
}

function dokeyring_select()
{
	try {
		initialize_openpgp();

		var id = $('#keyringselkey').val();
		id = id.trim();
		if (id == "") {
			window.alert("Please provide a key ID or fingerprint");
			return false;
		}
		openpgp.keyring.getWebCryptoPairById(id).then(
			function (r) {
				var pair = r.target.result;

				if (pair == null) {
					window.alert("Could not fetch key " + id);
					return;
				}
				generatedKeypair = pair;
				$('textarea#genkeypub').val(pair.publicKeyArmored);
				if (pair.privateKeyArmored != null)
					$('textarea#genkeypriv').val(pair.privateKeyArmored);
				else
					$('textarea#genkeypriv').val('Private key not extractable');
				window.alert("Looks like we fetched a key!");
			},
			function (e) {
				window.alert("Could not fetch key " + id +
				    ": " + e.target.result);
			}
		);
	} catch (err) {
		console.log(err.toString()); console.log(err); console.log(err.stack);
		window.alert("dokeyring_select() error: " + err);
	}
	return false;
}

function dokeyring()
{
	try {
		if (submitButton == "weball") {
			return dokeyring_weball();
		} else if (submitButton == "select") {
			return dokeyring_select();
		} else if (submitButton != "listall") {
			window.alert("Internal signtest error: dokeyring() invoked with an unexpected submitButton value: " + submitButton);
			return false;
		}
		initialize_openpgp();

		var keys = openpgp.keyring.privateKeys;
		var s = "Private keyring: " + keys.length + " key" +
		    (keys.length != 1? "s": "") + "\n";
		for (var i = 0; i < keys.length; i++) {
			console.log(keys[i]);
			s += "Key " + util.hexstrdump(keys[i].keyId) + "\n";
			var pair = keys[i].obj.privateKeyPacket.webCryptoPair;
			if (pair == null) {
				s += "- no WebCrypto info\n\n";
				continue;
			}
			s += "- provider " + pair.webProvider +
			    " id " + pair.keyId + "\n";
			for (var ktype in pair.webKeys) {
				var wk = pair.webKeys[ktype];
				s += "  - " + ktype + ": type " + wk.type +
				    " name " + wk.name +
				    " id " + wk.id +
				    "\n";
			}

			var wpair = openpgp_webcrypto_pair2webcrypto_fetch(pair.keyId);
			if (wpair == null) {
				s += "- no corresponding WebCrypto entry?!\n\n";
				continue;
			}
			s += "- corresponding provider " + wpair.webProvider +
			    " id " + wpair.keyId + "\n";
			for (var ktype in wpair.webKeys) {
				var wk = wpair.webKeys[ktype];
				s += "  - " + ktype + ": type " + wk.type +
				    " name " + wk.name +
				    " id " + wk.id +
				    "\n";
			}
			s += "\n";
		}
		$('textarea#keyringkeys').val(s);
	} catch (err) {
		console.log(err.toString()); console.log(err); console.log(err.stack);
		window.alert("dokeyring() error: " + err);
	}
	return false;
}
