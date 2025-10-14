"use strict";

const expect = require("chai").expect;
const should = require("chai").should(); // eslint-disable-line no-unused-vars
const xpath = require("xpath");
const xmldom = require("@xmldom/xmldom");

const metadata = require("../lib/metadata");

const entityFixtures = require("./fixtures/entities");

describe("Metadata creation and ingestion functions", function() {

	describe("buildIDPMetadata", function() {

		const simpleIDP = entityFixtures.simpleIDP;
		const idpWithCredentials = entityFixtures.simpleIDPWithCredentials;

		it("should describe a simple IDP as valid XML", function() {

			const xml = metadata.buildIDPMetadata(simpleIDP);
			const node = new xmldom.DOMParser().parseFromString(xml, "text/xml");
			xml.should.not.be.null;
			node.should.not.be.null;

			xpath.select("//*[local-name(.)='IDPSSODescriptor']", node)
				.length.should.equal(1);
			xpath.select("//*[local-name(.)='SingleSignOnService']", node)
				.length.should.equal(2);
		});

		it("should describe an IDP with credentials appropreately", function() {

			const xml = metadata.buildIDPMetadata(idpWithCredentials);
			const node = new xmldom.DOMParser().parseFromString(xml, "text/xml");
			xml.should.not.be.null;
			node.should.not.be.null;

			xpath.select("//*[local-name(.)='IDPSSODescriptor']", node)
				.length.should.equal(1);
			xpath.select("//*[local-name(.)='SingleSignOnService']", node)
				.length.should.equal(2);
			xpath.select("//*[local-name(.)='KeyDescriptor']", node)
				.length.should.equal(idpWithCredentials.credentials.length);
		});

	});

	describe("buildIDPMetadata and getIDPFromMetadata", function() {

		it("Should get an IDP config matching the supplied IDP as a result of ingesting metadata", function() {

			const idp = entityFixtures.simpleIDPWithCredentials;

			const encoded = metadata.buildIDPMetadata(idp);
			const decoded = metadata.getIDPFromMetadata(encoded);

			decoded.should.not.be.null;
			decoded.entityID.should.equal(idp.entityID);
			decoded.endpoints.login.post.should.equal(idp.endpoints.login);
			decoded.endpoints.login.redirect.should.equal(idp.endpoints.login);
			decoded.credentials.should.not.be.null;
			decoded.credentials[0].certificate.should.not.be.null;
			decoded.credentials[0].certificate.should.equal(idp.credentials[0].certificate);  // TODO: fix brittle string comp
			expect(decoded.requireSignedRequests).to.be.truthy;
		});
	});

	describe("buildSPMetadata", function() {

		const simpleSP = entityFixtures.simpleSP;
		const spWithCredentials = entityFixtures.simpleSPWithCredentials;

		it("should describe a simple SP as valid XML", function() {

			const xml = metadata.buildSPMetadata(simpleSP);
			const node = new xmldom.DOMParser().parseFromString(xml, "text/xml");
			xml.should.not.be.null;
			node.should.not.be.null;

			xpath.select("//*[local-name(.)='SPSSODescriptor']", node)
				.length.should.equal(1);
			xpath.select("//*[local-name(.)='AssertionConsumerService']", node)
				.length.should.equal(2);
		});

		it("should describe an SP with credentials appropreately", function() {

			const xml = metadata.buildSPMetadata(spWithCredentials);
			const node = new xmldom.DOMParser().parseFromString(xml, "text/xml");
			xml.should.not.be.null;
			node.should.not.be.null;

			xpath.select("//*[local-name(.)='SPSSODescriptor']", node)
				.length.should.equal(1);
			xpath.select("//*[local-name(.)='AssertionConsumerService']", node)
				.length.should.equal(2);
			xpath.select("//*[local-name(.)='KeyDescriptor']", node)
				.length.should.equal(spWithCredentials.credentials.length * 2);
		});

	});

	describe("buildSPMetadata and getSPFromMetadata", function() {

		it("Should get an SP config matching the supplied SP as a result of ingesting metadata", function() {

			const sp = entityFixtures.simpleSPWithCredentials;

			const encoded = metadata.buildSPMetadata(sp);
			const decoded = metadata.getSPFromMetadata(encoded);

			decoded.should.not.be.null;
			decoded.entityID.should.equal(sp.entityID);
			decoded.endpoints.assert.post.should.equal(sp.endpoints.assert);
			decoded.endpoints.assert.redirect.should.equal(sp.endpoints.assert);
			decoded.credentials.should.not.be.null;
			decoded.credentials[0].certificate.should.not.be.null;
			decoded.credentials[0].certificate.should.equal(sp.credentials[0].certificate);  // TODO: fix brittle string comp
			expect(decoded.requireSignedResponses).to.be.truthy;
		});
	});
});
