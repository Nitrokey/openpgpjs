var openpgp_initialized = false;
var generatedKeypair = null;
var submitButton = 'none';

function initialize_openpgp()
{
	if (openpgp_initialized)
		return true;

	window.alert("Initializing OpenPGPjs...");
	//openpgp.init(["domcrypt", "aiee", "browser", "nfwebcrypto", "own", "quux"]);
	//openpgp.init(["owncrypto"]);
	//openpgp.init(["domcrypt"]);
	openpgp.init(["cryptostick"]);
	//openpgp.init(["nfwebcrypto"]);
	openpgp_initialized = true;
}

function dogenkey()
{
	try {
		window.alert("window.cryptostick is " + window.cryptostick);
		openpgp_webcrypto_get_all_keys("cryptostick").then(
			function (res) {
				window.alert("Got a result from getKeyByName(null)!");
				var data = res.target.result;
				s = "";
				for (var i = 0; i < data.length; i++) {
					s += data[i].name + " ... ";
				}
				window.alert(s);

				if (data.length == 0) {
					window.alert("Not testing any keys :)");
					return;
				}

				var idx;
				if (data.length == 1) {
					window.alert("About to try for the first key...");
					idx = 0;
				} else {
					window.alert("About to try for the second key...");
					idx = 1;
				}
				openpgp_webcrypto_get_key("cryptostick", data[idx].name, data[idx].id).then(
					function (r) {
						window.alert("Got a result from getKeyByName('" + data[idx].name + "')");
						window.alert("name " + r.target.result.name + ", id " + r.target.result.id);
					},
					function (e) {
						window.alert("openpgp_webcrypto_get_key('" + data[0].name + "', '" + data[0].id + "') returned an error: " + e.target.result);
					}
				);
			},
			function (res) {
				console.log("RDBG getKeyByName(null) error:"); console.log(res);
				window.alert("getKeyByName(null) error: " + res.target.result);
			}
		);
		throw 'RDBG FIXME: nothing more :)';
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
			foundKey(r.target.result);
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
		window.alert("dosign() error: " + err);
	}
	return false;
}
