"use strict";

const expect = require("chai").expect;
const should = require("chai").should();
const xmlbuilder = require("xmlbuilder");
const xmldom = require("xmldom");
const xpath = require("xpath");

const entityFixtures = require("./fixtures/entities");
const credentialFixtures = require("./fixtures/credentials");
const samlFixtures = require("./fixtures/saml");
const sampleRequest = samlFixtures("onelogin/onelogin-saml-request.xml");

describe("Protocol binding functions", function() {

	const protocolBindings = require("../lib/protocol-bindings");

	describe("expandBindings", function() {
		it("should expand abbreviated protocol bindings within an endpoint list", function() {
			const endpoints = {
				login: "localhost/login"
			};
			const expanded = protocolBindings.expandBindings(endpoints);
			expanded.login.post.should.equal(endpoints.login);
			expanded.login.redirect.should.equal(endpoints.login);
		});
	});

	describe("chooseBinding", function() {
		it("should select a post binding if given a choice of post or redirect bindings", function() {
			const recipient = {
				endpoints: {
					login: "localhost/login"
				}
			};
			const choice = protocolBindings.chooseBinding(recipient, "login");
			choice.binding.should.equal("post");
			choice.url.should.equal(recipient.endpoints.login);
		});

		it("should select a redirect binding if it is specified as the default", function() {
			const recipient = {
				endpoints: {
					login: {
						post: "localhost/login",
						redirect: "localhost/login/redirect",
						_default: "redirect"
					}
				}
			};
			const choice = protocolBindings.chooseBinding(recipient, "login");
			choice.binding.should.equal("redirect");
			choice.url.should.equal(recipient.endpoints.login.redirect);
		});
	});

	describe("applyPostBinding and getDataFromPostBinding", function() {

		it("can work together to transmit and recieve an unsigned payload", function() {

			const payload = sampleRequest;

			const bound = protocolBindings.applyPostBinding(
				entityFixtures.simpleSP,
				entityFixtures.simpleIDP,
				payload,
				false,
				entityFixtures.simpleIDP.endpoints.login.post,
				"login"
			);

			const recieved = protocolBindings.getDataFromPostBinding(bound.formBody);

			recieved.should.not.be.null;
			recieved.payload.should.equal(payload);
		});

		it("can work together to transmit and recieve a signed payload", function() {

			const payload = sampleRequest;

			const bound = protocolBindings.applyPostBinding(
				entityFixtures.simpleSPWithCredentials,
				entityFixtures.simpleIDPWithCredentials,
				payload,
				false,
				entityFixtures.simpleIDP.endpoints.login.post,
				"login"
			);

			const recieved = protocolBindings.getDataFromPostBinding(bound.formBody);

			recieved.should.not.be.null;
			recieved.payload.should.not.equal(payload);
			const recievedDOM = new xmldom.DOMParser().parseFromString(recieved.payload);
			xpath.select("//*[local-name(.)='Signature']", recievedDOM)[0].should.not.be.null;
		});
	});

	describe("applyRedirectBinding and getDataFromRedirectBinding", function() {

		it("can work together to transmit and recieve an unsigned payload", function() {

			const payload = sampleRequest;

			const bound = protocolBindings.applyRedirectBinding(
				entityFixtures.simpleSP,
				entityFixtures.simpleIDP,
				payload,
				false,
				entityFixtures.simpleIDP.endpoints.login.redirect
			);

			const recieved = protocolBindings.getDataFromRedirectBinding(bound.url.query);

			recieved.should.not.be.null;
			recieved.payload.should.equal(payload);
			expect(recieved.verifySignature).to.be.falsey;
		});

		it("can work together to transmit and recieve a signed payload - and verify its signature", function() {

			const payload = sampleRequest;

			const bound = protocolBindings.applyRedirectBinding(
				entityFixtures.simpleSPWithCredentials,
				entityFixtures.simpleIDPWithCredentials,
				payload,
				false,
				entityFixtures.simpleIDP.endpoints.login.redirect
			);

			const recieved = protocolBindings.getDataFromRedirectBinding(bound.url.query);

			recieved.should.not.be.null;
			recieved.payload.should.equal(payload);

			recieved.verifySignature(entityFixtures.simpleSPWithCredentials).should.be.true;
		});
	});
});
