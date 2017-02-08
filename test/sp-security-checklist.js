"use strict";

const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
const should = chai.should(); // eslint-disable-line no-unused-vars

const xmldom = require("xmldom");
const xpath  = require("xpath");
const entityFixtures = require("./fixtures/entities");
const ModelStub      = require("./fixtures/model-stub");
//const samlFixtures   = require("./fixtures/saml");
const credentials = require("../lib/util/credentials");
const randomID    = require("../lib/util/random-id");
const signing     = require("../lib/util/signing");
const errors      = require("../lib/errors");
const namespaces  = require("../lib/namespaces");
const select      = xpath.useNamespaces(namespaces);
const moment      = require("moment");

/**
 * Tests for SP request construction and response handling for the
 * security-conscious. The protocol binding layer is tested seperately, as
 * its functionality is shared by both IDPs and SPs.
 */
describe("Service Provider security checklist", function() {

	const requestConstruction = require("../lib/request-construction");
	const responseConstruction = require("../lib/response-construction");
	const responseHandling = require("../lib/response-handling");

	const sp = entityFixtures.simpleSPWithCredentials;
	const idp = entityFixtures.simpleIDPWithCredentials;
	const idpWithLatency = entityFixtures.simpleIDPWithLatency;

	describe("Response:Assertion:Subject:SubjectConfirmation:SubjectConfirmationData element (With Latency)", function() {

		let model, requestID;

		beforeEach(function() {
			model = ModelStub.whichResolvesIDP(idpWithLatency);
			requestID = randomID();
			return model.storeRequestID(requestID, idpWithLatency);
		});

		function buildValidResponse() {
			return responseConstruction.createSuccessResponse(
				sp,
				idpWithLatency,
				requestID,
				randomID(),
				{ "FirstName": "Bob" },
				sp.endpoints.assert
			);
		}

		function parse(xml) {
			return new xmldom.DOMParser().parseFromString(xml);
		}
		
		function consume(doc, skipSigning) {

			let useSP = sp;
			let xml = new xmldom.XMLSerializer().serializeToString(doc);

			// sign the resulting document - normally we sign at the protocol
			// layer, so here we can guarentee that a signature is not yet
			// in place
			if (!skipSigning) {
				xml = signing.signXML(
					xml,
					{
						reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
						action: "after"
					},
					"//*[local-name(.)='Response']",
					credentials.getCredentialsFromEntity(idp, "signing")[0]
				);
			}
			// otherwise, use a modified SP which does not require signing
			else {
				useSP = Object.assign({}, sp, { requireSignedResponses: false });
			}

			return responseHandling.processResponse(model, useSP, {
				payload: xml,
				binding: "post",
				isResponse: true
			});
		}
		consume.withoutSigning = function(doc) {
			return consume(doc, true);
		};

		it("must NOT be rejected if it contains a 'NotOnOrAfter' or 'NotBefore' as 1 sec latency ", function() {
			return buildValidResponse()
				.then(parse)
				.then(doc => {
					const conditions = select("//saml:Conditions", doc)[0];
					const NotBefore = moment();

					NotBefore.add(1, "seconds");
					conditions.setAttribute("NotBefore", NotBefore.toISOString());

					const NotOnOrAfter = moment();
					NotOnOrAfter.subtract(1, "seconds");
					conditions.setAttribute("NotOnOrAfter", NotOnOrAfter.toISOString());

					return doc;
				})
				.then(consume).should.eventually.be.fulfilled;
		});

	});

	describe("outgoing AuthnRequests", function() {

		const model = ModelStub.whichResolvesIDP(idp);
		let authnRequest;

		before(function() {
			const dest = idp.endpoints.login;
			return requestConstruction.createAuthnRequest(sp, idp, model, dest)
				.then(xml => {
					const doc = new xmldom.DOMParser().parseFromString(xml);
					doc.childNodes.length.should.equal(1);
					authnRequest = doc.childNodes[0];
					authnRequest.localName.should.equal("AuthnRequest");
				});
		});

		it("must contain an 'ID' attribute", function() {
			authnRequest.getAttribute("ID").should.not.be.null;
		});

		it("must contain an 'Issuer' element matching the SP's entity ID", function() {
			const issuer = select("saml:Issuer", authnRequest)[0];
			issuer.should.not.be.null;
			issuer.childNodes.length.should.equal(1);
			issuer.childNodes[0].nodeValue.should.equal(sp.entityID);
		});
	});

	describe("incoming Responses with assertions", function() {

		let model, requestID;

		beforeEach(function() {
			model = ModelStub.whichResolvesIDP(idp);
			requestID = randomID();
			return model.storeRequestID(requestID, idp);
		});

		function buildValidResponse() {
			return responseConstruction.createSuccessResponse(
				sp,
				idp,
				requestID,
				randomID(),
				{ "FirstName": "Bob" },
				sp.endpoints.assert
			);
		}

		function buildResponseWithoutAttributes() {
			return responseConstruction.createSuccessResponse(
				sp,
				idp,
				requestID,
				randomID(),
				null,
				sp.endpoints.assert
			);
		}

		function parse(xml) {
			return new xmldom.DOMParser().parseFromString(xml);
		}

		function consume(doc, skipSigning) {

			let useSP = sp;
			let xml = new xmldom.XMLSerializer().serializeToString(doc);

			// sign the resulting document - normally we sign at the protocol
			// layer, so here we can guarentee that a signature is not yet
			// in place
			if (!skipSigning) {
				xml = signing.signXML(
					xml,
					{
						reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
						action: "after"
					},
					"//*[local-name(.)='Response']",
					credentials.getCredentialsFromEntity(idp, "signing")[0]
				);
			}
			// otherwise, use a modified SP which does not require signing
			else {
				useSP = Object.assign({}, sp, { requireSignedResponses: false });
			}

			return responseHandling.processResponse(model, useSP, {
				payload: xml,
				binding: "post",
				isResponse: true
			});
		}
		consume.withoutSigning = function(doc) {
			return consume(doc, true);
		};

		describe("Response element", function() {

			it("must be rejected if the 'InResponseTo' attribute does not match a previous AuthnRequest", function() {
				model = ModelStub.whichResolvesIDP(idp);
				model.reqIDStore = {}; // nuke previous requests in model
				return buildValidResponse()
					.then(parse)
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors[0].should.have.string("InResponseTo");
					});
			});

			it("must be rejected if a Destination attribute is not present", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						select("//samlp:Response", doc)[0].removeAttribute("Destination");
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors[0].should.have.string("destination is invalid");
					});
			});

			it("must be rejected if the Destination attribute does not match the SP's ACS endpoint", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						select("//samlp:Response", doc)[0].setAttribute("Destination", "http://invalid");
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors[0].should.have.string("destination is invalid");
					});
			});
		});

		describe("Response:Issuer element", function() {

			it("must be rejected if it exists and does not match the SP's entity ID", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						select("//samlp:Response/saml:Issuer", doc)[0].textContent = "an-invalid-issuer";
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors[0].should.have.string("Issuer element does not match IDP's entity ID");
					});
			});

			it("may not be present", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const resp = select("//samlp:Response", doc)[0];
						resp.removeChild(select("saml:Issuer", resp)[0]);
						select("//samlp:Response/saml:Issuer", doc).length.should.equal(0);
						return doc;
					})
					// signing code targets the "Issuer" element that we removed
					.then(consume.withoutSigning).should.eventually.be.fulfilled;
			});
		});

		describe("Response:Assertion element", function() {

			it("must be present if not an error response", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const resp = select("//samlp:Response", doc)[0];
						resp.removeChild(select("//saml:Assertion", resp)[0]);
						select("//saml:Assertion", doc).length.should.equal(0);
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors[0].should.have.string("no Assertion in response");
					});
			});

			it("must be rejected if it does not contan an 'Issuer' element with a value matching the IDP's entity ID", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const assertion = select("//saml:Assertion", doc)[0];
						assertion.removeChild(select("saml:Issuer", assertion)[0]);
						select("//saml:Assertion/saml:Issuer", doc).length.should.equal(0);
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors[0].should.have.string("Issuer does not match IDP's entity ID");
					});
			});
		});



		describe("Response:Assertion:Subject:SubjectConfirmation element", function() {

			it("must be present", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const subject = select("//saml:Assertion/saml:Subject", doc)[0];
						subject.removeChild(select("saml:SubjectConfirmation", subject)[0]);
						select("//saml:SubjectConfirmation", doc).length.should.equal(0);
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors[0].should.have.string("no SubjectConfirmation in Assertion");
					});
			});

			it("must contain a 'Method' attribute with value 'urn:oasis:names:tc:SAML:2.0:cm:bearer'", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const subjectConf = select("//saml:SubjectConfirmation", doc)[0];
						subjectConf.getAttribute("Method").should.equal("urn:oasis:names:tc:SAML:2.0:cm:bearer");
						subjectConf.removeAttribute("Method");
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors[0].should.have.string("subject confirmation method must be bearer");
					});
			});
		});

		describe("Response:Assertion:Subject:SubjectConfirmation:SubjectConfirmationData element", function() {

			it("must contain 'Recipient', 'NotOnOrAfter', and 'InResponseTo' attributes when using a high-security configuration", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const subjectConf = select("//saml:SubjectConfirmationData", doc)[0];
						subjectConf.removeAttribute("Recipient");
						subjectConf.removeAttribute("NotOnOrAfter");
						subjectConf.removeAttribute("InResponseTo");
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors.length.should.equal(3);
						err.errors.join("").should.have.string("Recipient is required");
						err.errors.join("").should.have.string("NotOnOrAfter is required");
						err.errors.join("").should.have.string("InResponseTo is required");
					});
			});

			it("must be rejected if the 'Recipient' attribute does not match one of the SP's ACS endpoints", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const subjectConf = select("//saml:SubjectConfirmationData", doc)[0];
						subjectConf.setAttribute("Recipient", "https://google.com");
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors.length.should.equal(1);
						err.errors.join("").should.have.string("Recipient is not valid");
					});
			});

			it("must be rejected if the 'NotOnOrAfter' attribute reflects a date matching or prior to the current instant", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const subjectConf = select("//saml:SubjectConfirmationData", doc)[0];
						subjectConf.setAttribute("NotOnOrAfter", new Date().toISOString());
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors.length.should.equal(1);
						err.errors.join("").should.have.string("NotOnOrAfter is in the past");
					});
			});

			it("must be rejected if the 'InResponseTo' does not correspond to an AuthnRequest's ID", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const subjectConf = select("//saml:SubjectConfirmationData", doc)[0];
						subjectConf.setAttribute("InResponseTo", "-1");
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors.length.should.equal(1);
						err.errors.join("").should.have.string("InResponseTo is not valid");
					});
			});
		});

		describe("Response:Assertion:Conditions element", function() {

			it("must be rejected if it contains a 'NotBefore' date in the future", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const conditions = select("//saml:Conditions", doc)[0];
						const newDate = new Date();
						newDate.setYear("3030");
						conditions.setAttribute("NotBefore", newDate.toISOString());
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors.length.should.equal(1);
						err.errors.join("").should.have.string("NotBefore is in the future");
					});
			});

			it("must be rejected if it contains a 'NotOnOrAfter' date in the past", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const conditions = select("//saml:Conditions", doc)[0];
						const newDate = new Date();
						newDate.setYear("2000");
						conditions.setAttribute("NotOnOrAfter", newDate.toISOString());
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors.length.should.equal(1);
						err.errors.join("").should.have.string("NotOnOrAfter is in the past");
					});
			});
		});

		describe("Response:Assertion:Conditions:AudienceRestriction element", function() {

			it("must be rejected if it does not contain an 'Audience' element matching the SP's entity ID", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const audience = select("//saml:Conditions/saml:AudienceRestriction/saml:Audience", doc)[0];
						audience.textContent = "google.com";
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors.length.should.equal(1);
						err.errors.join("").should.have.string("Audience does not match");
					});
			});
		});
		
		describe("Response:Assertion:AttributeStatement", function() {
			it("should be absent when not provided", function() {
				return buildResponseWithoutAttributes()
					.then(parse)
					.then(doc => {
						const attrStatement = select("//saml:AttributeStatement", doc)[0];
						should.not.exist(attrStatement);
					});
			});
		});

		describe("Response:Assertion:AuthnStatement", function() {

			it("must be present", function() {
				return buildValidResponse()
					.then(parse)
					.then(doc => {
						const authnStatement = select("//saml:AuthnStatement", doc)[0];
						doc.removeChild(authnStatement);
						return doc;
					})
					.then(consume).should.eventually.be.rejected
					.then(err => {
						err.should.be.an.instanceof(errors.ValidationError);
						err.errors.length.should.equal(1);
						err.errors.join("").should.have.string("Assertion must contain at least one AuthnStatement");
					});
			});
		});

		it("should pass validation when all of these conditions are met", function() {
			return buildValidResponse()
				.then(parse)
				.then(consume)
				.then(result => {
					result.should.not.be.null;
					result.idp.should.not.be.null;
					result.nameID.should.not.be.null;
					result.nameIDFormat.should.not.be.null;
					result.attributes.length.should.equal(1);
				});
		});

		it("should pass validation when attributes are not provided", function() {
			return buildResponseWithoutAttributes()
				.then(parse)
				.then(consume)
				.then(result => {
					result.should.not.be.null;
					result.idp.should.not.be.null;
					result.nameID.should.not.be.null;
					result.nameIDFormat.should.not.be.null;
					result.attributes.length.should.equal(0);
				});
		});
	});
});
