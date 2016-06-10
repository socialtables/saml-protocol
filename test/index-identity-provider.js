"use strict";

const assert = require("chai").assert;
const expect = require("chai").expect;
const should = require("chai").should();

describe("exports.IdentityProvider", function() {

	const IdentityProvider = require("../lib").IdentityProvider;
	const errors = require("../lib/errors");
	const signling = require("../lib/util/signing");

	const entityFixtures = require("./fixtures/entities");
	const credentialFixtures = require("./fixtures/credentials");
	const modelStub = require("./fixtures/model-stub");
	const samlFixtures = require("./fixtures/saml");

	describe("consumePostAuthnRequest", function() {

		it("accepts an unsigned AuthnRequest encoded with a POST binding when signing is not required", function() {

			const idp = new IdentityProvider(
				Object.assign({}, entityFixtures.simpleIDPWithCredentials, {
					requireSignedRequests: false
				}),
				modelStub.whichResolvesSP(entityFixtures.oneloginSP)
			);

			const requestPayload = samlFixtures("onelogin/onelogin-saml-request.xml");
			const sampleRequestBase64 = new Buffer(requestPayload, "utf8").toString("base64");
			const formParams = { SAMLRequest: sampleRequestBase64 };

			return idp.consumePostAuthnRequest(formParams).then(result => {
				result.idp.entityID.should.equal(entityFixtures.simpleIDP.entityID);
				result.sp.entityID.should.equal(entityFixtures.oneloginSP.entityID);
				result.requestID.should.not.be.null;
				result.nameID.should.not.be.null;
			});
		});

		it("rejects an unsigned AuthnRequest encoded with a POST binding when signing is required", function() {

			const idp = new IdentityProvider(
				Object.assign({}, entityFixtures.simpleIDPWithCredentials, {
					requireSignedRequests: true
				}),
				modelStub.whichResolvesSP(entityFixtures.oneloginSP)
			);

			const requestPayload = samlFixtures("onelogin/onelogin-saml-request.xml");
			const sampleRequestBase64 = new Buffer(requestPayload, "utf8").toString("base64");
			const formParams = { SAMLRequest: sampleRequestBase64 };

			return idp.consumePostAuthnRequest(formParams)
				.then(result => {
					assert.fail("should have thrown an error");
				})
				.catch(err => {
					err.should.not.be.null;
					err.message.should.match(/IDP requires authentication requests to be signed/);
				});
		});

		it("accepts an AuthnRequest encoded with a POST binding with a valid signature when signing is required", function() {

			const idp = new IdentityProvider(
				Object.assign({}, entityFixtures.simpleIDPWithCredentials, {
					requireSignedRequests: true
				}),
				modelStub.whichResolvesSP(Object.assign(
					{},
					entityFixtures.oneloginSP,
					{ credentials: [credentialFixtures.sp1] }
				))
			);

			// the signed onelogin example request payload has an invalid digest,
			// possibly due to mangled line endings; instead, we sign their
			// unsigned example and use that.
			let requestPayload = samlFixtures("onelogin/onelogin-saml-request.xml");
			requestPayload = require("../lib/util/signing").signXML(
				requestPayload,
				{
					reference: "//*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']",
					action: "after"
				},
				"//*[local-name(.)='AuthnRequest']",
				credentialFixtures.sp1,
				{ prefix: "ds" }
			);

			const sampleRequestBase64 = new Buffer(requestPayload, "utf8").toString("base64");
			const formParams = { SAMLRequest: sampleRequestBase64 };

			return idp.consumePostAuthnRequest(formParams).then(result => {
				result.idp.entityID.should.equal(entityFixtures.simpleIDP.entityID);
				result.sp.entityID.should.equal(entityFixtures.oneloginSP.entityID);
				result.requestID.should.not.be.null;
				result.nameID.should.not.be.null;
			});
		});
	});
});
