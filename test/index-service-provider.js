"use strict";

const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
const expect = chai.expect;
chai.use(chaiAsPromised);
chai.should();

const xmldom = require("xmldom");
const xpath = require("xpath");
const zlib = require("zlib");

describe("ServiceProvider", function() {

	const ServiceProvider = require("../lib").ServiceProvider;
	const responseConstruction = require("../lib/response-construction");
	const protocolBindings = require("../lib/protocol-bindings");
	const errors = require("../lib/errors");
	const metadata = require("../lib/metadata");
	const encryption = require("../lib/util/encryption");
	const signing = require("../lib/util/signing");

	const entityFixtures = require("./fixtures/entities");
	const credentialFixtures = require("./fixtures/credentials");
	const modelStub = require("./fixtures/model-stub");
	const samlFixtures = require("./fixtures/saml");

	describe("produceAuthnRequest", function() {

		let model;
		beforeEach(function() {
			model = new modelStub();
		});

		it("produces a valid POST-bound AuthnRequest descriptor for a POST-accepting IDP", function() {

			const sp = new ServiceProvider(entityFixtures.simpleSP, model);
			const idp = entityFixtures.simpleIDP;

			return sp.produceAuthnRequest(idp)
				.should.eventually.be.fulfilled
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.method.should.equal("POST");
					descriptor.contentType.should.equal("x-www-form-urlencoded");
					descriptor.formBody.should.not.be.null;
					descriptor.formBody.SAMLRequest.should.not.be.null;
					descriptor.url.should.not.be.null;
					descriptor.url.href.should.equal(idp.endpoints.login.post);

					const requestBase64 = descriptor.formBody.SAMLRequest;
					const requestXML = new Buffer(requestBase64, "base64").toString("utf8");
					const request = new xmldom.DOMParser().parseFromString(requestXML);
					xpath.select("//*[local-name(.)='AuthnRequest']", request).length.should.equal(1);
					xpath.select("//*[local-name(.)='Signature']", request).length.should.equal(0);
				});
		});

		it("produces a valid signed POST-bound AuthnRequest descriptor for a POST-accepting IDP", function() {

			const sp = new ServiceProvider(entityFixtures.simpleSPWithCredentials, model);
			const idp = entityFixtures.simpleIDPWithCredentials;

			return sp.produceAuthnRequest(idp)
				.should.eventually.be.fulfilled
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.method.should.equal("POST");
					descriptor.contentType.should.equal("x-www-form-urlencoded");
					descriptor.formBody.should.not.be.null;
					descriptor.formBody.SAMLRequest.should.not.be.null;
					descriptor.url.should.not.be.null;
					descriptor.url.href.should.equal(idp.endpoints.login);

					const requestBase64 = descriptor.formBody.SAMLRequest;
					const requestXML = new Buffer(requestBase64, "base64").toString("utf8");
					const request = new xmldom.DOMParser().parseFromString(requestXML);
					xpath.select("//*[local-name(.)='AuthnRequest']", request).length.should.equal(1);
					xpath.select("//*[local-name(.)='Signature']", request).length.should.equal(1);
					const sigNode = xpath.select("//*[local-name(.)='Signature']", request)[0];
					signing.validateXMLSignature(requestXML, sigNode, sp.sp.credentials[0]).should.equal(0);
				});
		});

		it("produces a valid REDIRECT-bound AuthnRequest descriptor for a REDIRECT-accepting IDP", function() {

			const sp = new ServiceProvider(entityFixtures.simpleSP, model);
			const idp = entityFixtures.oneloginRedirectIDP;

			return sp.produceAuthnRequest(idp)
				.should.eventually.be.fulfilled
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.method.should.equal("GET");
					descriptor.url.should.not.be.null;
					descriptor.url.href.should.equal(idp.endpoints.login.redirect);
					descriptor.url.query.should.not.be.null;
					descriptor.url.query.SAMLRequest.should.not.be.null;
					expect(descriptor.url.query.Signature).to.be.undefined;
					const requestBase64 = descriptor.url.query.SAMLRequest;
					const requestXML = zlib.inflateRawSync(new Buffer(requestBase64, "base64")).toString("utf8");
					const request = new xmldom.DOMParser().parseFromString(requestXML);
					xpath.select("//*[local-name(.)='AuthnRequest']", request).length.should.equal(1);
				});
		});

		it("produces a valid signed REDIRECT-bound AuthnRequest descriptor for a REDIRECT-accepting IDP", function() {

			const sp = new ServiceProvider(entityFixtures.simpleSPWithCredentials, model);
			const idp = entityFixtures.oneloginRedirectIDP;

			return sp.produceAuthnRequest(idp)
				.should.eventually.be.fulfilled
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.method.should.equal("GET");
					descriptor.url.should.not.be.null;
					descriptor.url.href.should.equal(idp.endpoints.login.redirect);
					descriptor.url.query.should.not.be.null;
					descriptor.url.query.SAMLRequest.should.not.be.null;
					descriptor.url.query.Signature.should.be.defined;
					const requestBase64 = descriptor.url.query.SAMLRequest;
					const requestXML = zlib.inflateRawSync(new Buffer(requestBase64, "base64")).toString("utf8");
					const request = new xmldom.DOMParser().parseFromString(requestXML);
					xpath.select("//*[local-name(.)='AuthnRequest']", request).length.should.equal(1);

					signing.verifyURLSignature(
						sp.sp.credentials[0].certificate,
						protocolBindings.constructSignaturePayload(descriptor.url.query),
						descriptor.url.query.SigAlg,
						descriptor.url.query.Signature
					).should.equal(true);
				});
		});
	});

	describe("consumePostResponse", function() {

		let model;

		beforeEach(function() {

			// spoof a state of having sent the request for this response
			model = modelStub.whichResolvesIDP(entityFixtures.oneloginIDP);
			model.storeRequestID("ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685", entityFixtures.oneloginIDP);
		})

		function signResponse(xml) {
			return signing.signXML(
				xml,
				{
					reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
					action: "after"
				},
				"//*[local-name(.)='Response']",
				entityFixtures.oneloginIDP.credentials[0]
			);
		}

		function signAssertion(xml) {
			return signing.signXML(
				xml,
				{
					reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
					action: "after"
				},
				"//*[local-name(.)='Assertion']",
				entityFixtures.oneloginIDP.credentials[0]
			);
		}

		function encryptAssertion(xml) {
			const doc = new xmldom.DOMParser().parseFromString(xml);
			const cred = entityFixtures.oneloginSP.credentials[0];
			return encryption
				.encryptAssertion(doc, cred)
				.then(doc => {
					return new xmldom.XMLSerializer().serializeToString(doc);
				});
		}

		function prepareAsPostRequest(responsePayload) {
			const responseBase64 = new Buffer(responsePayload, "utf8").toString("base64");
			const formParams = { SAMLResponse: responseBase64 };
			return formParams;
		}

		it("consumes a valid unsigned POST response", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: false
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(prepareAsPostRequest)
				.then(sp.consumePostResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("consumes a valid POST response with a signature in the Response element", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(signResponse)
				.then(prepareAsPostRequest)
				.then(sp.consumePostResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("consumes a valid POST response with a signature in the Assertion element", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(signAssertion)
				.then(prepareAsPostRequest)
				.then(sp.consumePostResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("consumes a valid encrypted POST response", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: false
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(encryptAssertion)
				.then(prepareAsPostRequest)
				.then(sp.consumePostResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("consumes a valid encrypted POST response with a signed assertion", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(signAssertion)
				.then(encryptAssertion)
				.then(prepareAsPostRequest)
				.then(sp.consumePostResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("consumes a valid double-signed, encrypted, POST response", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(signAssertion)
				.then(encryptAssertion)
				.then(signResponse)
				.then(prepareAsPostRequest)
				.then(sp.consumePostResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("rejects an invalid unsigned POST response", function() {

			// destination and other attributes will not match as we chose a differant SP
			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.simpleSP, {
					requireSignedResponses: false
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(prepareAsPostRequest)
				.then(sp.consumePostResponse.bind(sp))
				.should.eventually.be.rejected
				.then(error => {
					error.should.not.be.null;
					error.message.should.have.string("invalid assertion");
					error.errors.join(",").should.have.string("destination");
				});
		});

		it("rejects an otherwise-valid POST response with an invalid signature", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(signResponse)
				.then(xml => {
					const doc = new xmldom.DOMParser().parseFromString(xml);
					xpath.select("//*[local-name(.)='AttributeValue']", doc)[0].textContent = "changed";
					return new xmldom.XMLSerializer().serializeToString(doc);
				})
				.then(prepareAsPostRequest)
				.then(sp.consumePostResponse.bind(sp))
				.should.eventually.be.rejected
				.then(error => {
					error.should.not.be.null;
					error.message.should.have.string("invalid assertion");
					error.errors.join(",").should.have.string("signature");
				});
		});

		it("rejects an POST response without a signature when one is required", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(prepareAsPostRequest)
				.then(sp.consumePostResponse.bind(sp))
				.should.eventually.be.rejected
				.then(error => {
					error.should.not.be.null;
					error.message.should.have.string("invalid assertion");
					error.errors.join(",").should.have.string("signature");
				});
		});

		it("rejects a response that indicates an error occurred with a RejectionError", function() {

			const sp = new ServiceProvider(entityFixtures.oneloginSP, model);
			const failurePayload = responseConstruction.createAuthnFailureResponse(
				sp.sp,
				entityFixtures.oneloginIDP,
				"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685",
				"Something bad happened",
				sp.sp.endpoints.assert
			);

			return Promise.resolve(failurePayload)
				.then(prepareAsPostRequest)
				.then(sp.consumePostResponse.bind(sp))
				.should.eventually.be.rejected
				.then(error => {
					error.should.not.be.null;
					expect(error instanceof errors.RejectionError);
					error.message.should.have.string("IDP rejected AuthnRequest");
					error.message.should.have.string("Something bad happened");
				});
		});
	});

	describe("consumeRedirectResponse", function() {

		let model;

		beforeEach(function() {

			// spoof a state of having sent the request for this response
			model = modelStub.whichResolvesIDP(entityFixtures.oneloginIDP);
			model.storeRequestID("ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685", entityFixtures.oneloginIDP);
		})

		function signAssertion(xml) {
			return signing.signXML(
				xml,
				{
					reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
					action: "after"
				},
				"//*[local-name(.)='Assertion']",
				entityFixtures.oneloginIDP.credentials[0]
			);
		}

		function encryptAssertion(xml) {
			const doc = new xmldom.DOMParser().parseFromString(xml);
			const cred = entityFixtures.oneloginSP.credentials[0];
			return encryption
				.encryptAssertion(doc, cred)
				.then(doc => {
					return new xmldom.XMLSerializer().serializeToString(doc);
				});
		}

		function prepareAsRedirectRequest(xml) {

			// deflate, encode
			const responsePayload = zlib.deflateRawSync(xml).toString("base64");
			return {
				SAMLResponse: responsePayload,
				RelayState: "some-string"
			};
		}

		function signRedirectRequest(queryParams) {

			// compute signature
			const sigAlg = signing.supportedAlgorithms[0];
			const sigCredential = entityFixtures.oneloginIDP.credentials[0];

			queryParams.SigAlg = sigAlg;

			const payload = protocolBindings.constructSignaturePayload(queryParams);
			const signature = signing.createURLSignature(sigCredential.privateKey, payload, sigAlg);

			// apply query parameters
			queryParams.Signature = signature;
			return queryParams;
		}

		it("consumes a valid unsigned REDIRECT response", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: false
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(prepareAsRedirectRequest)
				.then(sp.consumeRedirectResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("rejects an otherwise-valid unsigned REDIRECT response if expecting a signature", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(prepareAsRedirectRequest)
				.then(sp.consumeRedirectResponse.bind(sp))
				.should.eventually.be.rejected
				.then(error => {
					error.should.not.be.null;
					error.errors[0].should.have.string("signature");
				});
		});

		it("consumes a valid REDIRECT response with a query signature", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(prepareAsRedirectRequest)
				.then(signRedirectRequest)
				.then(sp.consumeRedirectResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("consumes a valid REDIRECT response with a query signature and an Assertion signature", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(signAssertion)
				.then(prepareAsRedirectRequest)
				.then(signRedirectRequest)
				.then(sp.consumeRedirectResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("consumes a valid REDIRECT response with a query signature and an encrypted Assertion", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(encryptAssertion)
				.then(prepareAsRedirectRequest)
				.then(signRedirectRequest)
				.then(sp.consumeRedirectResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("consumes a valid REDIRECT response with a query signature, an Assertion signature, and an encrypted Assertion", function() {

			const sp = new ServiceProvider(
				Object.assign({}, entityFixtures.oneloginSP, {
					requireSignedResponses: true
				}),
				model
			);

			const responsePayload = samlFixtures("onelogin/onelogin-saml-response.xml");
			return Promise.resolve(responsePayload)
				.then(signAssertion)
				.then(encryptAssertion)
				.then(prepareAsRedirectRequest)
				.then(signRedirectRequest)
				.then(sp.consumeRedirectResponse.bind(sp))
				.then(descriptor => {
					descriptor.should.not.be.null;
					descriptor.idp.should.equal(entityFixtures.oneloginIDP);
					descriptor.nameID.should.not.be.null;
					descriptor.attributes.should.not.be.null;
					descriptor.attributes.length.should.equal(3);
				});
		});

		it("rejects a response that indicates an error occurred with a RejectionError", function() {

			const sp = new ServiceProvider(entityFixtures.oneloginSP, model);
			const failurePayload = responseConstruction.createAuthnFailureResponse(
				sp.sp,
				entityFixtures.oneloginIDP,
				"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685",
				"Something bad happened",
				sp.sp.endpoints.assert
			);

			return Promise.resolve(failurePayload)
				.then(prepareAsRedirectRequest)
				.then(sp.consumeRedirectResponse.bind(sp))
				.should.eventually.be.rejected
				.then(error => {
					error.should.not.be.null;
					expect(error instanceof errors.RejectionError);
					error.message.should.have.string("IDP rejected AuthnRequest");
					error.message.should.have.string("Something bad happened");
				});
		});
	});

	describe("produceSPMetadata", function() {

		it("should produce a metadata descriptor describing a simple SP", function() {

			const sp = new ServiceProvider(entityFixtures.simpleSP, null);
			const md = sp.produceSPMetadata();
			md.should.not.be.null;

			const spConfFromData = metadata.getSPFromMetadata(md);
			spConfFromData.entityID.should.equal(sp.sp.entityID);
			spConfFromData.credentials.length.should.equal(0);
		});

		it("should produce a metadata descriptor describing a complex SP", function() {

			const spConf = {
				entityID: "test.socialtables.com",
				credentials: [
					{
						use: "signing",
						certificate: credentialFixtures.sp1.certificate,
						privateKey: credentialFixtures.sp1.privateKey
					},
					{
						use: "encryption",
						certificate: credentialFixtures.sp2.certificate,
						privateKey: credentialFixtures.sp2.privateKey
					}
				],
				endpoints: {
					assert: {
						redirect: "test.socialtables.com/assert/redirect",
						post: "test.socialtables.com/assert/redirect"
					}
				},
				signAllRequests: true,
				requireSignedResponses: true
			};

			const sp = new ServiceProvider(spConf, null);
			const md = sp.produceSPMetadata();
			md.should.not.be.null;

			const spConfFromData = metadata.getSPFromMetadata(md);
			spConfFromData.entityID.should.equal(spConf.entityID);
			spConfFromData.credentials.length.should.equal(2);
			spConfFromData.credentials.forEach(credential => {
				credential.certificate.should.not.be.null;
				expect(credential.privateKey).not.to.be.defined;
			});

			spConfFromData.requireSignedResponses.should.be.true;
		});
	});

	describe("getIDPFromMetadata", function() {

		it("should produce an IDP config suitable for further use when provided metadata", function() {
			const md = samlFixtures("ssocircle/ssocircle-metadata.xml");
			const sp = new ServiceProvider(entityFixtures.simpleSP, null);
			const idp = sp.getIDPFromMetadata(md);
			idp.should.not.be.null;
			idp.entityID.should.equal("http://idp.ssocircle.com");
			idp.credentials.length.should.equal(2);
			idp.endpoints.login.should.be.defined;
		});
	});

	describe("should be able to complete an SSO flow with IdentityProvider", function() {

		const IdentityProvider = require("../lib").IdentityProvider;

		it("should learn about an IDP through metadata and do SSO", function() {

			const spModel = new modelStub();
			const idpModel = new modelStub();

			const sp = new ServiceProvider(entityFixtures.simpleSPWithCredentials, spModel);
			const idp = new IdentityProvider(entityFixtures.simpleIDPWithCredentials, idpModel);

			const spMD = sp.produceSPMetadata();
			const idpMD = idp.produceIDPMetadata();

			spModel.idpStub = sp.getIDPFromMetadata(idpMD);
			idpModel.spStub = idp.getSPFromMetadata(spMD);

			const userNameID = "123456789";
			const userAttributes = {
				FirstName: "Bobby",
				LastName: "Tables",
				EmailAddress: "bobby@socialtables.com"
			};

			return sp.produceAuthnRequest(spModel.idpStub)
				.then(spRequestDescriptor => {
					spRequestDescriptor.method.should.equal("POST");
					spRequestDescriptor.formBody.should.not.be.null;
					return idp.consumePostAuthnRequest(spRequestDescriptor.formBody);
				})
				.then(idpRequestDescriptor => {
					idpRequestDescriptor.sp.should.equal(idpModel.spStub);
					idpRequestDescriptor.requestID.should.not.be.null;
					idpRequestDescriptor.nameID.format.should.equal("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
					return idp.produceSuccessResponse(
						idpModel.spStub,
						idpRequestDescriptor.requestID,
						userNameID,
						userAttributes
					);
				})
				.then(idpResponseDescriptor => {
					idpResponseDescriptor.method.should.equal("POST");
					idpResponseDescriptor.formBody.should.not.be.null;
					return sp.consumePostResponse(idpResponseDescriptor.formBody);
				})
				.then(spResponseDescriptor => {
					spResponseDescriptor.idp.should.equal(spModel.idpStub);
					spResponseDescriptor.nameID.should.equal(userNameID);
					spResponseDescriptor.attributes.should.not.be.null;
					spResponseDescriptor.attributes.length.should.equal(3);
				});
		});
	});
});
