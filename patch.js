const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { pki, md } = require('node-forge');
const prompt = require('prompt');
const colors = require("@colors/colors/safe");

async function showPrompt() {
	prompt.message = colors.magenta('SSSL');

	prompt.start();

	const options = await prompt.get({
		properties: {
			nintendo_ca_g3_path: {
				description: colors.blue('Path to Nintendo CA - G3 (default to this directory)'),
				default: './CACERT_NINTENDO_CA_G3.pem'
			},
			private_key_path: {
				description: colors.blue('Path to certificate private key (will generate if not set)')
			},
			output_folder_path: {
				description: colors.blue('Output folder (default to this directory)'),
				default: './'
			}
		}
	});

	if (!fs.existsSync(options.nintendo_ca_g3_path)) {
		console.log(colors.bgRed('Invalid Nintendo CA - G3 path'));

		showPrompt();

		return;
	}

	if (options.private_key_path && !fs.existsSync(options.private_key_path)) {
		console.log(colors.bgRed('Invalid certificate private key path'));

		showPrompt();

		return;
	}

	if (!fs.existsSync(options.output_folder_path)) {
		console.log(colors.bgRed('Invalid output folder path'));

		showPrompt();

		return;
	}

	options.output_folder_path = path.resolve(options.output_folder_path);

	try {
		patchCA(options);


		console.log(colors.green(`Wrote patched CA to ${options.output_folder_path}/patched-ca.pem`));
		console.log(colors.green(`Wrote private key to ${options.output_folder_path}/private-key.pem`));
	} catch (error) {
		console.log(colors.bgRed(`Error patching CA: ${error}`));

		showPrompt();
	}
}

function patchCA(options) {
	// * Parse Nintendo CA - G3
	const nintendoCAG3PEM = fs.readFileSync(options.nintendo_ca_g3_path);
	const nintendoCAG3 = pki.certificateFromPem(nintendoCAG3PEM);

	let privateKey;
	let publicKey;

	if (options.private_key_path) {
		const privateKeyPEM = fs.readFileSync(options.private_key_path);
		privateKey = pki.privateKeyFromPem(privateKeyPEM);
		publicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e);
	} else {
		const keyPair = pki.rsa.generateKeyPair(2048);

		privateKey = keyPair.privateKey;
		publicKey = keyPair.publicKey;
	}

	// * Patch Nintendo CA - G3 with our new keys and identifer
	const patchedCA = pki.createCertificate();

	patchedCA.publicKey = publicKey; // * Condition 1, set a new CA public key
	patchedCA.serialNumber = nintendoCAG3.serialNumber;
	patchedCA.validity.notBefore = nintendoCAG3.validity.notBefore; // TODO - Make this configurable?
	patchedCA.validity.notAfter = nintendoCAG3.validity.notAfter; // TODO - Make this configurable?
	patchedCA.setIssuer(nintendoCAG3.subject.attributes);
	patchedCA.setSubject(nintendoCAG3.subject.attributes);
	patchedCA.setExtensions([
		...nintendoCAG3.extensions.filter(({ name }) => name !== 'authorityKeyIdentifier'), // * Remove old one
		{
			// * Condition 2, set a new authority key identifier extension
			// *
			// * node-forge has no docs for this extension. Taken from
			// * https://github.com/digitalbazaar/forge/blob/2bb97afb5058285ef09bcf1d04d6bd6b87cffd58/tests/unit/x509.js#L324-L329
			// * https://github.com/digitalbazaar/forge/blob/2bb97afb5058285ef09bcf1d04d6bd6b87cffd58/lib/x509.js#L2204-L2233
			name: 'authorityKeyIdentifier',
			keyIdentifier:  crypto.randomBytes(16).toString('ascii'),
			authorityCertIssuer: nintendoCAG3.issuer,
			serialNumber: nintendoCAG3.serialNumber
		}
	]);

	// * Self-sign the CA patched with the private key
	patchedCA.sign(privateKey, md.sha256.create()); // * sha256WithRSAEncryption

	// * Save the private key and patched CA
	fs.writeFileSync(`${options.output_folder_path}/patched-ca.pem`, pki.certificateToPem(patchedCA), 'utf8');
	fs.writeFileSync(`${options.output_folder_path}/private-key.pem`, pki.privateKeyToPem(privateKey), 'utf8');
}

showPrompt();