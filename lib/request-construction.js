"use strict";

const xmlbuilder = require("xmlbuilder");
const zlib       = require("zlib");

const namespaces       = require("./namespaces");
const protocol         = require("./protocol");
const protocolBindings = require("./protocol-bindings");
const randomID         = require("./util/random-id");
const signing          = require("./util/signing");

module.exports = {

	// method used by rest of app
	createBoundAuthnRequest,

	// internal methods exposed for testing
	createAuthnRequest
};

/**
 * Constructs and returns a description of how to direct the user to
 * an IDP, or throws an error.
 */
function createBoundAuthnRequest(sp, idp, model) {
	const idpBindingChoice = protocolBindings.chooseBinding(idp, "login");
	return createAuthnRequest(sp, idp, model, idpBindingChoice.url)
		.then(authnRequestXML => {
			return protocolBindings.applyBinding(sp, idp, authnRequestXML, false, "login", idpBindingChoice);
		});
}

/**
 * Creates an AuthnRequest and records its ID in redis
 * @param sp: service provider config
 * @param idp: identity provider config
 * @param model: model instance capable of persisting a request ID
 */
function createAuthnRequest(sp, idp, model, destinationURL) {

	// generate an ID - 21 random bytes should be unique enough
	const requestID = randomID();

	// choose which consumption endpoint and method the assertion should
	// come in on
	const spBindingChoice = protocolBindings.chooseBinding(sp, "assert");

	let nameIDFormat;
	if (sp.nameIDFormats) {
		nameIDFormat = sp.nameIDFormats[0];
	}
	else {
		nameIDFormat = protocol.NAMEIDFORMAT.UNSPECIFIED;
	}

	// build request payload
	const authnRequest = xmlbuilder
		.begin({
			separateArrayItems: true
		})
		.ele({
			"samlp:AuthnRequest": [  // request child elements are ordered
				{
					"@xmlns:samlp": namespaces.samlp,
					"@xmlns:saml": namespaces.saml,
					"@Version": "2.0",
					"@ID": requestID,
					"@IssueInstant": new Date().toISOString(),
					"@Destination": destinationURL,
					"@AssertionConsumerServiceURL": spBindingChoice.url,
					"@ProtocolBinding": spBindingChoice.longformURI,
				},
				{ "saml:Issuer": sp.entityID },
				(nameIDFormat ? { "samlp:NameIDPolicy": {
					"@Format": nameIDFormat,
					"@AllowCreate": true
				}} : null),
				{ "samlp:RequestAuthnContext": {
					"@Comparison": "exact",
					"saml:AuthnContextClassRef": protocol.AUTHNCONTEXT.PASSWORDPROTECTEDTRANSPORT
				}}
			].filter(exists => exists)
		})
		.end();

	// persist the request ID, return promise chain
	return model
		.storeRequestID(requestID, idp)
		.then(() => {
			return authnRequest;
		});
};
