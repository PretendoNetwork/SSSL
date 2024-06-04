const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { asn1, pki, md } = require('node-forge');
const prompt = require('prompt');
const colors = require('@colors/colors/safe');
const dotenv = require('dotenv');

const defaultOptions = {
	nintendo_ca_g3_path: './CACERT_NINTENDO_CA_G3.der',
	nintendo_ca_g3_format: 'der',
	ca_private_key_path: undefined,
	site_private_key_path: undefined,
	csr_path: undefined,
	common_name: '*',
	output_folder_path: './'
};

async function main() {
	dotenv.config();

	if (process.argv.includes('-i') || process.argv.includes('--interactive')) {
		showPrompt();

		return;
	}

	const options = {
		nintendo_ca_g3_path: process.env.NINTENDO_CA_G3_PATH || defaultOptions.nintendo_ca_g3_path,
		nintendo_ca_g3_format: process.env.NINTENDO_CA_G3_FORMAT || defaultOptions.nintendo_ca_g3_format,
		ca_private_key_path: process.env.CA_PRIVATE_KEY_PATH || defaultOptions.ca_private_key_path,
		site_private_key_path: process.env.SITE_PRIVATE_KEY_PATH || defaultOptions.site_private_key_path,
		csr_path: process.env.CSR_PATH || defaultOptions.csr_path,
		common_name: process.env.COMMON_NAME || defaultOptions.common_name,
		output_folder_path: process.env.OUTPUT_FOLDER_PATH || defaultOptions.output_folder_path
	};

	if (validateOptions(options)) {
		forgeCertificateChain(options);
	} else {
		throw new Error('Invalid options specified.');
	}
}

async function showPrompt() {
	prompt.message = colors.magenta('SSSL');

	prompt.start();

	const options = await prompt.get({
		properties: {
			nintendo_ca_g3_path: {
				description: colors.blue('Path to Nintendo CA - G3 certificate (default to this directory)'),
				default: defaultOptions.nintendo_ca_g3_path
			},
			nintendo_ca_g3_format: {
				description: colors.blue('Nintendo CA - G3 certificate format (must be "der" or "pem")'),
				default: defaultOptions.nintendo_ca_g3_format
			},
			ca_private_key_path: {
				description: colors.blue('Path to private key for forged CA (will generate if not set)'),
				default: defaultOptions.ca_private_key_path
			},
			site_private_key_path: {
				description: colors.blue('Path to private key for site certificate (will generate if not set)'),
				default: defaultOptions.site_private_key_path
			},
			csr_path: {
				description: colors.blue('Path to CSR (will generate if not set)'),
				default: defaultOptions.csr_path
			},
			common_name: {
				description: colors.blue('CN for site certificate (default to "*")'),
				default: defaultOptions.common_name
			},
			output_folder_path: {
				description: colors.blue('Output folder (default to this directory)'),
				default: defaultOptions.output_folder_path
			}
		}
	});

	if (validateOptions(options)) {
		try {
			forgeCertificateChain(options);
		} catch (error) {
			console.log(colors.bgRed(`Error patching CA: ${error}`));

			showPrompt();
		}
	} else {
		showPrompt();
	}
}

function validateOptions(options) {
	options.nintendo_ca_g3_path = path.resolve(options.nintendo_ca_g3_path);

	if (options.ca_private_key_path) {
		options.ca_private_key_path = path.resolve(options.ca_private_key_path);
	}

	if (options.site_private_key_path) {
		options.site_private_key_path = path.resolve(options.site_private_key_path);
	}

	if (options.csr_path) {
		options.csr_path = path.resolve(options.csr_path);
	}

	options.output_folder_path = path.resolve(options.output_folder_path);

	if (!fs.existsSync(options.nintendo_ca_g3_path)) {
		console.log(colors.bgRed('Invalid Nintendo CA - G3 path'));

		return false;
	}

	if (options.ca_private_key_path && !fs.existsSync(options.ca_private_key_path)) {
		console.log(colors.bgRed('Invalid CA private key path'));

		return false;
	}

	if (options.site_private_key_path && !fs.existsSync(options.site_private_key_path)) {
		console.log(colors.bgRed('Invalid site certificate private key path'));

		return false;
	}

	if (options.csr_path && !fs.existsSync(options.csr_path)) {
		console.log(colors.bgRed('Invalid CSR key path'));

		return false;
	}

	if (!fs.existsSync(options.output_folder_path)) {
		console.log(colors.bgRed('Invalid output folder path'));

		return false;
	}

	return true;
}

function forgeCertificateChain(options) {
	// * Parse Nintendo CA - G3
	let nintendoCAG3;
	if (options.nintendo_ca_g3_format === 'pem') {
		const nintendoCAG3PEM = fs.readFileSync(options.nintendo_ca_g3_path);
		nintendoCAG3 = pki.certificateFromPem(nintendoCAG3PEM);
	} else if (options.nintendo_ca_g3_format === 'der') {
		const nintendoCAG3DER = fs.readFileSync(options.nintendo_ca_g3_path, 'binary');
		const nintendoCAG3ASN1 = asn1.fromDer(nintendoCAG3DER);
		nintendoCAG3 = pki.certificateFromAsn1(nintendoCAG3ASN1);
	} else {
		throw new Error('Invalid Nintendo CA - G3 format: must be "der" or "pem"');
	}

	let caPrivateKey;
	let caPublicKey;

	if (options.ca_private_key_path) {
		const privateKeyPEM = fs.readFileSync(options.ca_private_key_path);
		caPrivateKey = pki.privateKeyFromPem(privateKeyPEM);
		caPublicKey = pki.setRsaPublicKey(caPrivateKey.n, caPrivateKey.e);
	} else {
		const keyPair = pki.rsa.generateKeyPair(2048);

		caPrivateKey = keyPair.privateKey;
		caPublicKey = keyPair.publicKey;
	}

	// * Patch Nintendo CA - G3 with our new keys and identifer
	const forgedCA = pki.createCertificate();

	forgedCA.publicKey = caPublicKey; // * Condition 1, set a new CA public key
	forgedCA.serialNumber = nintendoCAG3.serialNumber;
	forgedCA.validity.notBefore = nintendoCAG3.validity.notBefore; // TODO - Make this configurable?
	forgedCA.validity.notAfter = nintendoCAG3.validity.notAfter; // TODO - Make this configurable?
	forgedCA.setIssuer(nintendoCAG3.subject.attributes);
	forgedCA.setSubject(nintendoCAG3.subject.attributes);
	forgedCA.setExtensions([
		...nintendoCAG3.extensions.filter(({ name }) => name !== 'authorityKeyIdentifier'), // * Remove old one
		{
			// * Condition 2, set a new authority key identifier extension
			// *
			// * node-forge has no docs for this extension. Taken from
			// * https://github.com/digitalbazaar/forge/blob/2bb97afb5058285ef09bcf1d04d6bd6b87cffd58/tests/unit/x509.js#L324-L329
			// * https://github.com/digitalbazaar/forge/blob/2bb97afb5058285ef09bcf1d04d6bd6b87cffd58/lib/x509.js#L2204-L2233
			name: 'authorityKeyIdentifier',
			keyIdentifier: crypto.randomBytes(16).toString('ascii'),
			authorityCertIssuer: nintendoCAG3.issuer,
			serialNumber: nintendoCAG3.serialNumber
		}
	]);

	// * Self-sign the CA patched with the private key
	forgedCA.sign(caPrivateKey, md.sha256.create()); // * sha256WithRSAEncryption

	// * The below SSL certificate settings from from https://github.com/KaeruTeam/nds-constraint?tab=readme-ov-file#generating-trusted-certificates
	// TODO - Check other certificate settings and update these

	// * Read or create the site RSA key pair
	let sitePrivateKey;
	let sitePublicKey;

	if (options.site_private_key_path) {
		const privateKeyPEM = fs.readFileSync(options.site_private_key_path);
		sitePrivateKey = pki.privateKeyFromPem(privateKeyPEM);
		sitePublicKey = pki.setRsaPublicKey(sitePrivateKey.n, sitePrivateKey.e);
	} else {
		const keyPair = pki.rsa.generateKeyPair(1024); // TODO - Make this configurable?

		sitePrivateKey = keyPair.privateKey;
		sitePublicKey = keyPair.publicKey;
	}

	// * Read or create the CSR (Certificate Signing Request)
	let csr;

	if (options.csr_path) {
		const csrPEM = fs.readFileSync(options.csr_path);
		csr = pki.certificationRequestFromPem(csrPEM);
	} else {
		csr = pki.createCertificationRequest();
	}

	// * Update the CN and resign
	csr.publicKey = sitePublicKey;
	csr.setSubject([
		// TODO - Add the ability to set more of these?
		{
			name: 'commonName',
			value: options.common_name
		}
	]);
	csr.sign(sitePrivateKey);

	// * Create the new site SSL certificate and sign it with the forged CA
	const siteCertificate = pki.createCertificate();

	siteCertificate.serialNumber = new Date().getTime().toString(); // TODO - Make this configurable?
	siteCertificate.validity.notBefore = new Date(); // TODO - Make this configurable?
	siteCertificate.validity.notAfter = new Date(); // TODO - Make this configurable?
	siteCertificate.validity.notAfter.setDate(siteCertificate.validity.notBefore.getDate() + 3650); // TODO - Make this configurable?
	siteCertificate.setSubject(csr.subject.attributes);
	siteCertificate.setIssuer(forgedCA.subject.attributes);
	siteCertificate.publicKey = csr.publicKey;

	siteCertificate.sign(caPrivateKey, md.sha1.create()); // TODO - Make this configurable? What other signatures work for the Wii U

	// * Create the cert chain
	const chain = `${pki.certificateToPem(siteCertificate)}\n${pki.certificateToPem(forgedCA)}\n`;

	// * Save everything to disk
	// TODO - Write public keys?
	fs.writeFileSync(`${options.output_folder_path}/forged-ca.pem`, pki.certificateToPem(forgedCA), 'utf8');
	console.log(colors.green(`Wrote forged CA to ${options.output_folder_path}/forged-ca.pem`));
	fs.writeFileSync(`${options.output_folder_path}/forged-ca-private-key.pem`, pki.privateKeyToPem(caPrivateKey), 'utf8');
	console.log(colors.green(`Wrote forged CA private key to ${options.output_folder_path}/forged-ca-private-key.pem`));
	fs.writeFileSync(`${options.output_folder_path}/ssl-cert.pem`, pki.certificateToPem(siteCertificate), 'utf8');
	console.log(colors.green(`Wrote SSL certificate to ${options.output_folder_path}/ssl-cert.pem`));
	fs.writeFileSync(`${options.output_folder_path}/ssl-cert-private-key.pem`, pki.privateKeyToPem(sitePrivateKey), 'utf8');
	console.log(colors.green(`Wrote SSL certificate private key to ${options.output_folder_path}/ssl-cert-private-key.pem`));
	fs.writeFileSync(`${options.output_folder_path}/csr.csr`, pki.certificationRequestToPem(csr), 'utf8'); // TODO - Better name
	console.log(colors.green(`Wrote CSR to ${options.output_folder_path}/csr.csr`));
	fs.writeFileSync(`${options.output_folder_path}/cert-chain.pem`, chain, 'utf8');
	console.log(colors.green(`Wrote certificate chain to ${options.output_folder_path}/cert-chain.pem`));
}

main();
