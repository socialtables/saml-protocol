"use strict";

const crypto = require("crypto");
const SignedXml  = require("xml-crypto").SignedXml;

const pemFormatting = require("./pem-formatting");

// we export this list for use in metadata
const supportedAlgorithms = [
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1"
];

module.exports = {
	createURLSignature,
	verifyURLSignature,
	signXML,
	validateXMLSignature,
	resolveSignatureAlgorithm,
	supportedAlgorithms,
	chooseSignatureAlgorithm
};

// map node crypto shorthand signature algo names to their
// fully qualified URLs, and the URLs to themselves for
// easy reference.
const sigAlgLookup = {
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
	"RSA-SHA1":   "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
	"RSA-SHA256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	"RSA-SHA512": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
	default: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
};

// map signature algorithm URLs to crypto algorithm names
const cryptoAlgLookup = {
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1": "RSA-SHA1",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "RSA-SHA256",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "RSA-SHA512"
};

function resolveSignatureAlgorithm(sigAlg) {
	return sigAlgLookup[sigAlg] || sigAlgLookup.default;
}

/**
 * Creates a signature for use in query-param encoded GET requests.
 * xml-crypto already includes signing and verification logic, so
 * really we're just adding a level of algorithm name resolution and
 * payload formation.
 * @param privateKeyPem: private key in PEM format
 * @param signedPayload: payload string to sign
 */
function createURLSignature(privateKeyPem, signedPayload, sigAlg) {
	const privateKeyPemWithHeaders = pemFormatting.addPEMHeaders("RSA PRIVATE KEY", privateKeyPem);
	const signingAlgorithmName = resolveSignatureAlgorithm(sigAlg);
	const cryptoAlgName = cryptoAlgLookup[signingAlgorithmName];
	
	const signer = crypto.createSign(cryptoAlgName);
	signer.update(signedPayload);
	return signer.sign(privateKeyPemWithHeaders, "base64");
}

/**
 * Verifies a signature from a query-param encoded GET request.
 * xml-crypto already includes signing and verification logic, so
 * really we're just adding a level of algorithm name resolution and
 * payload formation.
 * @param certPem: certificate PEM
 * @param signedPayload: payload string on which to verify signature
 * @param signature: signature parameter
 */
function verifyURLSignature(certPem, signedPayload, sigAlg, signature) {
	const certPemWithHeaders = pemFormatting.addPEMHeaders("CERTIFICATE", certPem);
	const signingAlgorithmName = resolveSignatureAlgorithm(sigAlg);
	const cryptoAlgName = cryptoAlgLookup[signingAlgorithmName];
	
	const verifier = crypto.createVerify(cryptoAlgName);
	verifier.update(signedPayload);
	return verifier.verify(certPemWithHeaders, signature, "base64");
}

/**
 * XML signature generator - signs an XML document at the specified location
 *
 * @param xml: raw XML document string to sign
 * @param signatureLocation: location in document to place signature
 * @param signedXPath: XPath of node to sign in document
 * @param credentials: object containing a certificate and private key (PEM)
 * @param options: options including 'prefix' and 'signatureAlgorithm'
 */
function signXML(xml, signatureLocation, signedXPath, credentials, options) {

	options = options || {};

	// create and configure xml-crypto SignedXml instance
	const signatureAlgorithm = resolveSignatureAlgorithm(options.signatureAlgorithm);
	const privateKey = pemFormatting.addPEMHeaders("RSA PRIVATE KEY", credentials.privateKey);
	
	const signer = new SignedXml({
		privateKey: privateKey,
		publicCert: credentials.certificate,
		signatureAlgorithm: signatureAlgorithm,
		canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
		getKeyInfoContent: SignedXml.getKeyInfoContent
	});

	signer.addReference({
		xpath: signedXPath,
		transforms: [
			"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
			"http://www.w3.org/2001/10/xml-exc-c14n#"
		],
		digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1"
	});

	// compute signature and return signed XML document string
	signer.computeSignature(xml, {
		prefix: options.prefix || "ds",
		location: signatureLocation || ""
	});

	return signer.getSignedXml();
}

/**
 * XML signature validatior - validates a single XML signature
 * @param xml: raw XML string containing the signature's referenced element
 * @param signatureNode: XML Signature node to validate
 * @param credential: object containing a certificate (PEM)
 * @return: 0 indicating success, or an array with a single error message
 */
function validateXMLSignature(xml, signatureNode, credential) {

	const sigCheck = new SignedXml({
		publicCert: credential.certificate
	});
	sigCheck.loadSignature(signatureNode);
	const isValid = sigCheck.checkSignature(xml);
	if (isValid) {
		return 0;
	}
	else {
		// In xml-crypto 6.x, validationErrors is no longer available
		// Return a simple error array for backward compatibility
		return ["Signature validation failed"];
	}
}

/**
 * Chooses a signature algorithm that both the IDP and SP support, using the
 * supported algorithm list (which is ordered by favorability).
 * @param parties: a list of parties which need to support the chosen algorithm.
 */
function chooseSignatureAlgorithm(parties) {

	let choices = supportedAlgorithms;
	parties.forEach(entity => {
		if (entity.algorithms && entity.algorithms.signing) {
			choices = choices.filter(choice => {
				return (entity.algorithms.signing.indexOf(choice) != -1);
			});
		}
	});
	if (choices.length > 0) {
		return choices[0];
	}
	else {
		throw new Error("Unable to identify a signing algorithm supported by" +
			"both the IDP and SP.");
	}
}
