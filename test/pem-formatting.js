"use strict";

const should = require("chai").should(); // eslint-disable-line no-unused-vars

describe("PEM formatting utilities", function() {

	const pemFormatting = require("../lib/util/pem-formatting");
	const credentialFixtures = require("./fixtures/credentials");

	const headersRe = /-----BEGIN [0-9A-Z ]+-----[^-]*-----END [0-9A-Z ]+-----/g;
	const certPem = credentialFixtures.idp1.certificate;

	before("cert fixture should not be null", function() {
		certPem.should.not.be.null;
	});

	describe("addPEMHeaders", function() {
		it("should correctly apply PEM headers to a certificate", function() {
			const strippedCertPem = pemFormatting.stripPEMHeaders(certPem);
			headersRe.test(strippedCertPem).should.be.falsey;
			const reappliedCertPem = pemFormatting.addPEMHeaders("CERTIFICATE", strippedCertPem);
			headersRe.test(reappliedCertPem).should.be.truthy;
		});
		it("should not add PEM headers to certificates that already possess them", function() {
			const reappliedCertPem = pemFormatting.addPEMHeaders("CERTIFICATE", certPem);
			reappliedCertPem.should.equal(certPem);
		});
	});

	describe("stripPEMHeaders", function() {
		let strippedCertPem;
		it("should correctly strip PEM headers from a certificate", function() {
			strippedCertPem = pemFormatting.stripPEMHeaders(certPem);
			strippedCertPem.should.not.be.null;
			headersRe.test(strippedCertPem).should.be.falsey;
		});
		it("should allow pre-stripped PEM certitificates to pass through", function() {
			const doubleStripped = pemFormatting.stripPEMHeaders(strippedCertPem);
			doubleStripped.should.equal(strippedCertPem);
		});
	});
});
