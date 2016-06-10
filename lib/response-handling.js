"use strict";

const xmldom      = require("xmldom");
const xpath       = require("xpath");
const zlib        = require("zlib");

const signing          = require("./util/signing");
const credentials      = require("./util/credentials");
const encryption       = require("./util/encryption");
const errors           = require("./errors");
const namespaces       = require("./namespaces");
const protocolBindings = require("./protocol-bindings");

const DOMParser       = xmldom.DOMParser;
const ValidationError = errors.ValidationError;

const select = xpath.useNamespaces(namespaces);

module.exports = {

	// methods used by rest of app
	processResponse,
	mapUserAttributes,

	// internals exposed for testing
	checkStatus,
	extractUserAttributes,
};

/**
 * Entrypoint for assertion processing - takes an SAML assertion
 * and returns a description of it's contents if the everything checks
 * out.
 * @param model: model for IDP and request lookup
 * @param sp: Service Provider config object
 * @param samlResponse: SAML response passed from protocol layer
 * @returns: a description of the nameID and claims in the response
 * @throws: errors in case of failure
 */
function processResponse(model, sp, samlResponse) {

	// decode and parse the SAML document
	let doc = new DOMParser().parseFromString(samlResponse.payload);

	// choose the first Issuer node from the document, which
	// should reflect the assertion's IDP
	const issuer = select("//saml:Issuer/text()", doc)[0];
	if (!issuer) {
		throw new errors.ProtocolError("Unable to identify issuer");
	}

	let idp;
	let validator;
	let assertion;

	// look up IDP corresponding to this response
	return model
		.getIdentityProvider(issuer.nodeValue)
		.catch(err => {
			throw new ProtocolError("Unable to identify IDP", err);
		})
		.then(resolvedIDP => {

			// construct IDP, validator
			idp = resolvedIDP;
			validator = new ResponseValidator(sp, idp, model);

			// ensure status is success; rejection error thrown otherwise
			checkStatus(doc, idp);

			// the REDIRECT protocol binding uses query-level signatures,
			// so invoke the protocol level check if supported.
			if (samlResponse.verifySignature) {
				validator.hasValidSignature = samlResponse.verifySignature(idp);
			}

			// for POST responses, the signature may be in the top-level
			// Response, or it may be inside the Assertion, which may be
			// encrypted. validate all unencrypted signatures now.
			else {
				validator.validateAllSignatures(samlResponse.payload, doc);
			}

			// next, decrypt the assertion if necessary
			if (select("//saml:EncryptedAssertion", doc).length) {

				// remove the top-level signature, as it is now invalid
				select("//ds:Signature", doc).forEach(sigNode => {
					doc.removeChild(sigNode);
				})

				const encryptCreds = credentials.getCredentialsFromEntity(idp, "encryption");
				return encryption
					.decryptAssertion(doc, encryptCreds)
					.then(newDoc => {

						doc = newDoc;
						assertion = select("//saml:Assertion", doc)[0];

						const newDocXML = new xmldom.XMLSerializer().serializeToString(doc);
						validator.validateAllSignatures(newDocXML, assertion);
					});
			} else {
				assertion = select("//saml:Assertion", doc)[0];
			}
		})
		.then(() => {
			// do conditions and protocol validations
			validator.validateSignatureRequirement();
			return validator.validateResponseDocument(doc);
		})
		.then(() => {
			// throw an error with the aggregate validation issues if necessary
			if (!validator.isValid()) {
				throw new errors.ValidationError(
					"invalid assertion",
					validator.getErrors(),
					sp,
					idp,
					assertion
				);
			}
		})
		.then(() => {
			// if possible, make the request ID as processed to avoid playback attacks
			if (model.invalidateRequestID) {
				return model.invalidateRequestID(validator.inResponseTo, idp);
			}
		})
		.then(() => {
			// prepare and return assertion payload descriptor
			const nameIDNode = select("//saml:Subject/saml:NameID", assertion)[0];
			const nameID = select("./text()", nameIDNode)[0].nodeValue;
			const nameIDFormat = nameIDNode.getAttribute("Format") || protocol.NAMEIDFORMAT.undefined;
			return {
				idp: idp,
				nameID: nameID,
				nameIDFormat: nameIDFormat,
				attributes: extractUserAttributes(assertion)
			};
		});
}

/**
 * Checks for failure messages from the IDP, throws accordingly
 * @param doc: document
 * @param idp: identity probider config
 */
function checkStatus(doc, idp) {

	const statusNode = select("//samlp:StatusCode", doc)[0];
	const statusCodeAttr = statusNode.getAttribute("Value");
	const statusCodeMatch = statusCodeAttr.match(
		/urn\:oasis\:names\:tc\:SAML\:2.0\:status\:(.*)/
	);

	// Success status means all good
	if (statusCodeMatch[1] == "Success") {
		return statusCodeMatch[1];
	}
	else {  // otherwise, we won't be able to proceed
		const messageNodes = select("//samlp:StatusMessage/text()", doc);
		const messageStrings = messageNodes.map(node => node.nodeValue);
		let errBody = "IDP rejected AuthnRequest with status: " + statusCodeMatch[1];
		if (messageStrings.length) {
			errBody += " and messages: " + messageStrings.join(", ");
		}
		throw new errors.RejectionError(errBody);
	}
}

/**
 * Extracts usable user attributes from a given assertion.
 * @param assertion: SAML assertion
 * @return: a list of attribute descriptor objects
 */
function extractUserAttributes(assertion) {

	const attributeStatement = select("//saml:AttributeStatement", assertion)[0];
	const attributes = select("saml:Attribute", attributeStatement);

	return attributes.map(attrNode => {
		let attrName = attrNode.getAttribute("Name");
		let friendlyName = attrNode.getAttribute("FriendlyName");
		let attrVals = select("saml:AttributeValue/text()", attrNode)
			.map(n => n.nodeValue)
			.filter(n => n);

		return {
			name: attrName,
			friendlyName: friendlyName,
			values: attrVals
		};
	});
}

/**
 * User attribute mapper - optional processing phase which maps
 * IDP-produced attributes to service-provider user fields based on a provided
 * attribute map. Helps to simplify service-provider usage pattern.
 * @param attributes: array of attribute descriptors
 * @param attributeMapping: attribute mapping to use
 * @return: mapped attributes in an object
 */
function mapUserAttributes(attributes, attributeMapping) {

	const invertedAttributeMap = pendingAttributes
		.reduce((map, key) => {
			const sources = attributeMapping[key];
			sources.forEach(source => {
				map[source] = key;
			});
			return map;
		}, {});

	return attributes.reduce((result, attribute) => {
		let destKey = invertedAttributeMap[attribute.name.toLowerCase()];
		if (!destKey) {
			if (attribute.friendlyName) {
				destKey = invertedAttributeMap[attribute.friendlyName.toLowerCase()];
			}
		}
		if (destKey) {
			let attrVal = attribute.values;
			if (attrVal.length < 2) {
				attrVal = attrVal[0];
			}
			result[destKey] = attrVal;
		}
		return result;
	}, {});
}

// from here, its validators all the way down

/**
 * SAML Response validatior - validates decrypted SAMLResponse document nodes
 * @param sp: service provider descriptor
 * @param idp: identity provider descriptor
 * @param model: model used to verify inResponseTo's referened ID
 */
function ResponseValidator(sp, idp, model) {

	this.sp = sp;
	this.idp = idp;
	this.model = model;

	this.errorMessages = [];
	this.hasValidSignature = false;
	this.inResponseTo = null;

	// allow model to override date lookup so that we can test
	// with assertions created in the past
	this.getNow = model.getNow || function() {
		return new Date();
	};
}

ResponseValidator.prototype.addError = function(message) {
	this.errorMessages.push(message);
};

ResponseValidator.prototype.isValid = function() {
	return !this.errorMessages.length;
};

ResponseValidator.prototype.getErrors = function() {
	return this.errorMessages;
};

/**
 * SAML response payload data validator. Validates everything except
 * signatures, which must be done separately to handle cases where signing
 * and encryption are employed together. Use this as the main entrypoint
 * for data validations.
 *
 * @param doc: fully-decrypted SAML document
 * @return: a promise fulfilled after validation completes
 */
ResponseValidator.prototype.validateResponseDocument = function(doc) {

	// ensure that exactly one response node is present
	const responseNodes = select("//samlp:Response", doc);
	if (responseNodes.length != 1) {
		this.addError("Document must contain exactly one Response node");
		return Promise.resolve();  // nothing left to do
	}

	const responseNode = responseNodes[0];

	// check destination
	const destination = responseNode.getAttribute("Destination");
	const endpoints = protocolBindings.expandBindings(this.sp.endpoints);
	const validDestinations = [
		endpoints.assert.get,
		endpoints.assert.post
	].filter(ep => ep);
	if (validDestinations.indexOf(destination) == -1) {
		this.addError("Response destination is invalid");
	}

	// check optional issuer element outside Assertion
	const issuer = select("saml:Issuer/text()", responseNode).toString();
	if (issuer && issuer !== this.idp.entityID) {
		this.addError("Issuer element does not match IDP's entity ID");
	}

	// validate InResponseTo to ensure it matches a request we sent.
	// this operation is asynchronous, so we return a promise of
	// completion
	const inResponseTo = responseNode.getAttribute("InResponseTo");
	return this.verifyInResponseTo(inResponseTo, this.idp)
		.catch(() => {
			this.addError("invalid InResponseTo in Response node");
		})
		.then(() => {
			const assertion = select("saml:Assertion", responseNode)[0];
			if (!assertion) {
				this.addError("no Assertion in response");
			}
			else {
				return this.validateAssertion(assertion);
			}
		});
};

/**
 * Validates an Assertion
 * @param assertion: an SAML Assertion node
 * @return: a promise chain
 */
ResponseValidator.prototype.validateAssertion = function(assertion) {

	// ensure that the assertion came from the right place
	// unlike the parent document's Issuer, this Issuer element is REQUIRED
	const issuer = select("saml:Issuer/text()", assertion).toString();
	if (issuer != this.idp.entityID) {
		this.addError("Issuer does not match IDP's entity ID");
	}

	// run the rest of the validations, return the resulting promise chain
	return Promise.all([
		this.validateSubjectConfirmation(assertion),
		this.validateConditions(assertion),
		this.validateAuthnStatement(assertion)
	]);
}

/**
 * Validates a SubjectConfirmation node inside an assertion. According to the
 * proticol, there can be more than one. Most implementations only produce
 * one in reality.
 * @param assertion: Assertion element on which to validate the confirmation
 * @return: a promise chain
 */
ResponseValidator.prototype.validateSubjectConfirmation = function(assertion) {

	const subjectConfirmation = select("//saml:SubjectConfirmation", assertion)[0];
	if (!subjectConfirmation) {
		this.addError("no SubjectConfirmation in Assertion");
		return Promise.resolve();
	}

	const method = subjectConfirmation.getAttribute("Method");
	if (method != "urn:oasis:names:tc:SAML:2.0:cm:bearer") {
		this.addError("subject confirmation method must be bearer");
	}

	const data = select("//saml:SubjectConfirmationData", subjectConfirmation)[0];
	if (!data) {
		this.addError("subject confirmation does not contain a data element");
		return Promise.resolve();
	}

	const recipient = data.getAttribute("Recipient");
	const notOnOrAfter = data.getAttribute("NotOnOrAfter");
	const inResponseTo = data.getAttribute("InResponseTo");

	if (recipient) {

		const endpoints = protocolBindings.expandBindings(this.sp.endpoints);
		const validRecipients = [
			endpoints.assert.get,
			endpoints.assert.post
		].filter(ep => ep);

		if ( validRecipients.indexOf(recipient) == -1 ) {
			this.addError("SubjectConfirmationData.Recipient is not valid");
		}
	}
	else {
		this.addError("SubjectConfirmationData.Recipient is required");
	}

	if (notOnOrAfter) {
		if (new Date(notOnOrAfter) <= this.getNow()) {
			this.addError("SubjectConfirmationData.NotOnOrAfter is in the past");
		}
	}
	else {
		this.addError("SubjectConfirmationData.NotOnOrAfter is required");
	}

	if (inResponseTo) {

		// verify InResponseTo, return chain
		return this.verifyInResponseTo(inResponseTo)
			.catch(() => {
				this.addError("SubjectConfirmationData.InResponseTo is not valid");
			});
	}
	else {
		this.addError("SubjectConfirmationData.InResponseTo is required");
		return Promise.resolve();
	}
};

/**
 * Validates InResponseTo attribute - should be the same across all instances
 * in the request, and correspond to an issued AuthnRequest. This wraps the
 * model's implementation in a cache.
 * @param id: ID to check
 * @return a promise which will resolve if the ID was issued against this IDP
 */
ResponseValidator.prototype.verifyInResponseTo = function(id) {
	if (this.inResponseToChecked) {
		if (this.inResponseTo && (this.inResponseTo == id)) {
			return Promise.resolve();
		}
		else {
			return Promise.reject();
		}
	}
	else {
		return this.model.verifyRequestID(id, this.idp)
			.then(() => {
				this.inResponseTo = id;
			})
	}
}

/**
 * Assertion conditions validation
 * @param assertion: SAML assertion node
 * @return: a promise chain
 */
ResponseValidator.prototype.validateConditions = function(assertion) {

	// extract Conditions statement and process it if it exists
	const conditions = select("//saml:Conditions", assertion)[0];
	if (!conditions) {
		this.addError("no Conditions in Assertion");
		return Promise.resolve();
	}

	const notBefore = conditions.getAttribute("NotBefore");
	const notOnOrAfter = conditions.getAttribute("NotOnOrAfter");

	const now = this.getNow();

	if (notBefore) {
		if (new Date(notBefore) > now) {
			this.addError("Conditions.NotBefore is in the future");
		}
	}

	if (notOnOrAfter) {
		if (new Date(notOnOrAfter) <= now) {
			this.addError("Conditions.NotOnOrAfter is in the past");
		}
	}

	const audienceRestriction = select("saml:AudienceRestriction", conditions)[0];
	if (audienceRestriction) {
		let matchesAudience = false;
		const audiences = select("saml:Audience", audienceRestriction);
		audiences.forEach(audience => {
			if (audience.textContent == this.sp.entityID) {
				matchesAudience = true;
			}
		});
		if (!matchesAudience) {
			this.addError("Conditions.AudienceRestriction.Audience does not match the service provider");
		}
	}

	return Promise.resolve();
}

/**
 * Validates the presence of an AuthnStatement
 * @param assertion: Assertion node
 * @return: promise chain
 */
ResponseValidator.prototype.validateAuthnStatement = function(assertion) {

	const authnStatements = select("//saml:AuthnStatement", assertion);
	if (authnStatements.length === 0) {
		this.addError("Assertion must contain at least one AuthnStatement");
	}

	return Promise.resolve();
}


/**
 * XML signature validatior - accepts the raw XML instance and parsed XML
 * document for performance reasons. This gets called before and after
 * assertion decryption of the Response and Assertion as-necessary;
 * as per SAML 2.0 Core - subheading 6.2 "Combining Signatures and Encryption",
 * signed and encrypted assertions must be signed first and then encrypted - but
 * the parent Request object may also be signed, which can only be performed
 * once the assertion subdocument is encrypted. Therefore, this method is
 * optimized to facilitate the following flow:
 *
 * 1) check for and validate a top-level document signature
 * 2) decrypt any encrypted assertions
 * 3) check for and validate assertion signatures
 *
 * @param xml: raw XML document string
 * @param node: parsed XML document node upon which to validate signatures
 * @param cert: certificate to use for validation
 */
ResponseValidator.prototype.validateAllSignatures = function(xml, node) {

	const signatures = select("//ds:Signature", node);
	const creds = credentials.getCredentialsFromEntity(this.idp, "signing");

	// no signatures = no problem, we'll deal with response.numSignatures and
	// its implications in the parent function.
	if (signatures.length == 0) {
		return;
	}

	// validate all the sigs - there are edge cases where we have more than one!
	signatures.forEach(sig => {
		let sigValid = false;
		creds.forEach(credential => {
			const validationErrors = signing.validateXMLSignature(xml, sig, credential);
			if (!validationErrors) {
				sigValid = true;
			}
		});
		if (sigValid) {
			this.hasValidSignature = true;
		}
		else {
			this.addError("unable to validate signature");
		}
	});

	return;
}

/**
 * Signature requirement validator - adds an error if the SP is configured
 * to require signatures and no valid signatures have been encountered.
 */
ResponseValidator.prototype.validateSignatureRequirement = function() {
	if (this.sp.requireSignedResponses && !this.hasValidSignature) {
		this.addError("no valid signature in request");
	}
}
