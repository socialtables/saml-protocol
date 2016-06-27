"use strict";

const should = require("chai").should();
const xmldom = require("xmldom");
const xpath = require("xpath");

describe("Signing utilities", function() {

	const signing = require("../lib/util/signing");
	const namespaces = require("../lib/namespaces");

	const sampleXML = require("./fixtures/saml")("onelogin/onelogin-saml-request.xml");
	const credentials = require("./fixtures/credentials");
	const select = xpath.useNamespaces(namespaces);

	describe("XML signature generation and verification functions", function() {

		signing.supportedAlgorithms.forEach(alg => {
			it("should validate an XML document signed with " + alg.split("#")[1], function() {
				const signedXML = signing.signXML(
					sampleXML,
					{
						reference: "//*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']",
						action: "after"
					},
					"//*[local-name(.)='AuthnRequest']",
					credentials.sp1,
					{
						prefix: "ds",
						signatureAlgorithm: alg
					}
				);

				signedXML.should.not.be.null;

				const doc = new xmldom.DOMParser().parseFromString(signedXML);
				const sigNode = select("//ds:Signature", doc)[0];
				sigNode.should.not.be.null;
				select("//ds:SignatureMethod", sigNode)[0]
					.getAttribute("Algorithm").should.equal(alg);

				const hasErrors = signing.validateXMLSignature(signedXML, sigNode, credentials.sp1);
				hasErrors.should.equal(0);
			});
		});

		signing.supportedAlgorithms.forEach(alg => {
			it("should reject an XML document signed with " + alg.split("#")[1] + " with an invalid signature", function() {
				const signedXML = signing.signXML(
					sampleXML,
					{
						reference: "//*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']",
						action: "after"
					},
					"//*[local-name(.)='AuthnRequest']",
					credentials.sp1,
					{
						prefix: "ds",
						signatureAlgorithm: alg
					}
				);
				const doc = new xmldom.DOMParser().parseFromString(signedXML);
				const sigNode = select("//ds:Signature", doc)[0];
				sigNode.should.not.be.null;

				// permutate and reserialize the document, invalidating the signature
				select("//*[local-name(.)='Issuer']", doc)[0].setAttribute("href", "google.com");
				const modifiedXML = new xmldom.XMLSerializer().serializeToString(doc);

				const hasErrors = signing.validateXMLSignature(modifiedXML, sigNode, credentials.sp1);
				hasErrors.should.not.equal(0);
				hasErrors.should.be.an("array");
			});
		});
	});

	describe("URL signature generation and verification functions", function() {

		signing.supportedAlgorithms.forEach(alg => {
			it("should validate a payload signed using " + alg.split("#")[1], function() {
				const payload = sampleXML;
				const signature = signing.createURLSignature(
					credentials.sp1.privateKey,
					payload + alg,
					alg
				);
				const isValid = signing.verifyURLSignature(
					credentials.sp1.certificate,
					payload + alg,
					alg,
					signature
				);
				isValid.should.be.true;
			});
		});

		signing.supportedAlgorithms.forEach(alg => {
			it("should reject a payload signed using " + alg.split("#")[1] + " with an invalid signature", function() {
				const payload = sampleXML;
				const signature = signing.createURLSignature(
					credentials.sp1.privateKey,
					payload,
					"",
					alg
				);
				const isValid = signing.verifyURLSignature(
					credentials.sp1.certificate,
					payload.replace(/a/g,"b"),
					"",
					alg,
					signature
				);
				isValid.should.be.false;
			});
		});

	});
});
