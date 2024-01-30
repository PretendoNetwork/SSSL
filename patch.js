const fs = require('node:fs');
const crypto = require('node:crypto');
const { pki, md } = require('node-forge');

// * Parse Nintendo CA - G3
const nintendoCAG3PEM = fs.readFileSync('./CACERT_NINTENDO_CA_G3.pem')
const nintendoCAG3 = pki.certificateFromPem(nintendoCAG3PEM);

// * Generate a new key pair for the patched CA for condition 1
const newKeyPair = pki.rsa.generateKeyPair(2048);
const newCaPrivateKey = newKeyPair.privateKey;
const newCaPubliceKey = newKeyPair.publicKey;

// * Create a new CA based off Nintendo CA - G3. Just copy the values
const newCaCertificate = pki.createCertificate();

newCaCertificate.publicKey = newCaPubliceKey; // * Use the new public key, otherwise Charles complains
newCaCertificate.serialNumber = nintendoCAG3.serialNumber;
newCaCertificate.validity.notBefore = nintendoCAG3.validity.notBefore;
newCaCertificate.validity.notAfter = nintendoCAG3.validity.notAfter;
newCaCertificate.setIssuer(nintendoCAG3.subject.attributes);
newCaCertificate.setSubject(nintendoCAG3.subject.attributes);
newCaCertificate.setExtensions([
	...nintendoCAG3.extensions.filter(({ name }) => name !== 'authorityKeyIdentifier'), // * Remove old one
	{
		// * Set a new authority key identifier extension for condition 2
		// * node-forge has no docs for this extension. Taken from
		// * https://github.com/digitalbazaar/forge/blob/2bb97afb5058285ef09bcf1d04d6bd6b87cffd58/tests/unit/x509.js#L324-L329
		// * https://github.com/digitalbazaar/forge/blob/2bb97afb5058285ef09bcf1d04d6bd6b87cffd58/lib/x509.js#L2204-L2233
		name: 'authorityKeyIdentifier',
		keyIdentifier:  crypto.randomBytes(16).toString('ascii'),
		authorityCertIssuer: nintendoCAG3.issuer,
		serialNumber: nintendoCAG3.serialNumber
	}
]);

// * Self-sign the CA patched with the new private key
newCaCertificate.sign(newCaPrivateKey, md.sha256.create()); // * sha256WithRSAEncryption

// * Save the new private key and patched CA
const newCaPrivateKeyPem = pki.privateKeyToPem(newCaPrivateKey);
const newCaCertificatePem = pki.certificateToPem(newCaCertificate);

fs.writeFileSync('./private-key.pem', newCaPrivateKeyPem, 'utf8');
fs.writeFileSync('./patched-ca.pem', newCaCertificatePem, 'utf8');