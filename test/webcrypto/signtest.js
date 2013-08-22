var openpgp_initialized = false;
var generatedKeypair = null;

function dogenkey()
{
	try {
		window.alert("dogenkey() starting");
		if (!openpgp_initialized) {
			window.alert("Initializing OpenPGPjs...");
			//openpgp.init(["domcrypt", "aiee", "browser", "nfwebcrypto", "own", "quux"]);
			openpgp.init(["owncrypto"]);
			//openpgp.init(["nfwebcrypto"]);
			openpgp_initialized = true;
		}

		openpgp.generate_key_pair(1, 1024, "roam@openpgp.ringlet.net", "passstuff").then(
			function (pair) {
				generatedKeypair = pair;
				$('textarea#genkeypub').val(pair.publicKeyArmored);
			},
			function (e) {
				window.alert("dogenkey: openpgp.generate_key_pair() failed: " + e);
			}
		);
	} catch (err) {
		console.log(err.stack);
		window.alert("dogenkey() error: " + err);
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
		if (!openpgp_initialized) {
			window.alert("Initializing OpenPGPjs...");
			openpgp.init();
			openpgp_initialized = true;
		}

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
