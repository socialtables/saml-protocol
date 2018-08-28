import { should, assert } from 'chai';
import { DOMParser, XMLSerializer } from 'xmldom';
import xpath from 'xpath';
import moment from 'moment';

import entityFixtures from './fixtures/entities';
import ModelStub from './fixtures/model-stub';

import * as credentials from '../lib/util/credentials';
import randomID from '../lib/util/random-id';
import * as signing from '../lib/util/signing';
import { ValidationError } from '../lib/errors';
import namespaces from '../lib/namespaces';
import * as requestConstruction from '../lib/request-construction';
import * as responseConstruction from '../lib/response-construction';
import * as responseHandling from '../lib/response-handling';

should();
const select = xpath.useNamespaces(namespaces);
/**
 * Tests for SP request construction and response handling for the
 * security-conscious. The protocol binding layer is tested seperately, as
 * its functionality is shared by both IDPs and SPs.
 */
describe('Service Provider security checklist', function () {
  let sp = entityFixtures.simpleSPWithCredentials;
  let idp = entityFixtures.simpleIDPWithCredentials;
  const idpWithLatency = entityFixtures.simpleIDPWithLatency;

  describe('Response:Assertion:Subject:SubjectConfirmation:SubjectConfirmationData element (With Latency)', function () {
    let model;
    let requestID;

    beforeEach(function () {
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
        { FirstName: 'Bob' },
        sp.endpoints.assert,
      );
    }

    function parse(xml) {
      return new DOMParser().parseFromString(xml);
    }

    function consume(doc, skipSigning) {
      let useSP = sp;
      let xml = new XMLSerializer().serializeToString(doc);

      // sign the resulting document - normally we sign at the protocol
      // layer, so here we can guarentee that a signature is not yet
      // in place
      if (!skipSigning) {
        xml = signing.signXML(
          xml,
          {
            reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
            action: 'after',
          },
          "//*[local-name(.)='Response']",
          credentials.getCredentialsFromEntity(idp, 'signing')[0],
        );
      } else {
        // otherwise, use a modified SP which does not require signing
        useSP = {
          ...sp,
          requireSignedResponses: false,
        };
      }

      return responseHandling.processResponse(model, useSP, {
        payload: xml,
        binding: 'post',
        isResponse: true,
      });
    }
    consume.withoutSigning = function (doc) {
      return consume(doc, true);
    };

    it("must NOT be rejected if it contains a 'NotOnOrAfter' or 'NotBefore' as 1 sec latency ", async function () {
      const doc = await parse(await buildValidResponse());
      const conditions = select('//saml:Conditions', doc)[0];
      const NotBefore = moment();

      NotBefore.add(1, 'seconds');
      conditions.setAttribute('NotBefore', NotBefore.toISOString());

      const NotOnOrAfter = moment();
      NotOnOrAfter.subtract(1, 'seconds');
      conditions.setAttribute('NotOnOrAfter', NotOnOrAfter.toISOString());

      await consume(doc);
    });
  });

  describe('outgoing AuthnRequests', function () {
    const model = ModelStub.whichResolvesIDP(idp);
    let authnRequest;

    before(async function () {
      const dest = idp.endpoints.login;
      const xml = await requestConstruction.createAuthnRequest(sp, idp, model, dest);
      const doc = new DOMParser().parseFromString(xml);
      doc.childNodes.length.should.equal(1);
      authnRequest = doc.childNodes[0];
      authnRequest.localName.should.equal('AuthnRequest');
    });

    it("must contain an 'ID' attribute", function () {
      authnRequest.getAttribute('ID').should.not.be.null;
    });

    it("must contain an 'Issuer' element matching the SP's entity ID", function () {
      const issuer = select('saml:Issuer', authnRequest)[0];
      issuer.should.not.be.null;
      issuer.childNodes.length.should.equal(1);
      issuer.childNodes[0].nodeValue.should.equal(sp.entityID);
    });
  });

  describe('incoming Responses with assertions', function () {
    let model;
    let requestID;

    beforeEach(function () {
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
        { FirstName: 'Bob' },
        sp.endpoints.assert,
      );
    }

    function buildResponseWithoutAttributes() {
      return responseConstruction.createSuccessResponse(
        sp,
        idp,
        requestID,
        randomID(),
        null,
        sp.endpoints.assert,
      );
    }

    function parse(xml) {
      return new DOMParser().parseFromString(xml);
    }

    function consume(doc, skipSigning) {
      let useSP = sp;
      let xml = new XMLSerializer().serializeToString(doc);

      // sign the resulting document - normally we sign at the protocol
      // layer, so here we can guarentee that a signature is not yet
      // in place
      if (!skipSigning) {
        xml = signing.signXML(
          xml,
          {
            reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
            action: 'after',
          },
          "//*[local-name(.)='Response']",
          credentials.getCredentialsFromEntity(idp, 'signing')[0],
        );
      } else {
        // otherwise, use a modified SP which does not require signing
        useSP = { ...sp, requireSignedResponses: false };
      }

      return responseHandling.processResponse(model, useSP, {
        payload: xml,
        binding: 'post',
        isResponse: true,
      });
    }
    consume.withoutSigning = function (doc) {
      return consume(doc, true);
    };

    describe('Response element', function () {
      it("must be rejected if the 'InResponseTo' attribute does not match a previous AuthnRequest", async function () {
        model = ModelStub.whichResolvesIDP(idp);
        model.reqIDStore = {}; // nuke previous requests in model

        const doc = await parse(await buildValidResponse());
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors[0].should.have.string('InResponseTo');
        }
      });

      it('must be rejected if a Destination attribute is not present', async function () {
        const doc = await parse(await buildValidResponse());
        select('//samlp:Response', doc)[0].removeAttribute('Destination');
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors[0].should.have.string('destination is invalid');
        }
      });

      it("must be rejected if the Destination attribute does not match the SP's ACS endpoint", async function () {
        const doc = await parse(await buildValidResponse());
        select('//samlp:Response', doc)[0].setAttribute('Destination', 'http://invalid');
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors[0].should.have.string('destination is invalid');
        }
      });
    });

    describe('Response:Issuer element', function () {
      it("must be rejected if it exists and does not match the SP's entity ID", async function () {
        const response = await buildValidResponse();
        const doc = await parse(response);
        select('//samlp:Response/saml:Issuer', doc)[0].textContent = 'an-invalid-issuer';
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors[0].should.have.string("Issuer element does not match IDP's entity ID");
        }
      });

      it('may not be present', async function () {
        const response = await buildValidResponse();
        const doc = await parse(response);
        const resp = select('//samlp:Response', doc)[0];
        resp.removeChild(select('saml:Issuer', resp)[0]);
        select('//samlp:Response/saml:Issuer', doc).length.should.equal(0);
        // signing code targets the "Issuer" element that we removed
        await consume.withoutSigning(doc);
      });
    });

    describe('Response:Assertion element', function () {
      it('must be present if not an error response', async function () {
        const response = await buildValidResponse();
        const doc = await parse(response);
        const resp = select('//samlp:Response', doc)[0];
        resp.removeChild(select('//saml:Assertion', resp)[0]);
        select('//saml:Assertion', doc).length.should.equal(0);
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors[0].should.have.string('no Assertion in response');
        }
      });

      it("must be rejected if it does not contan an 'Issuer' element with a value matching the IDP's entity ID", async function () {
        const doc = await parse(await buildValidResponse());
        const assertion = select('//saml:Assertion', doc)[0];
        assertion.removeChild(select('saml:Issuer', assertion)[0]);
        select('//saml:Assertion/saml:Issuer', doc).length.should.equal(0);
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors[0].should.have.string("Issuer does not match IDP's entity ID");
        }
      });
    });

    describe('Response:Assertion:Subject:SubjectConfirmation element', function () {
      it('must be present', async function () {
        const doc = await parse(await buildValidResponse());
        const subject = select('//saml:Assertion/saml:Subject', doc)[0];
        subject.removeChild(select('saml:SubjectConfirmation', subject)[0]);
        select('//saml:SubjectConfirmation', doc).length.should.equal(0);
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors[0].should.have.string('no SubjectConfirmation in Assertion');
        }
      });

      it("must contain a 'Method' attribute with value 'urn:oasis:names:tc:SAML:2.0:cm:bearer'", async function () {
        const doc = await parse(await buildValidResponse());
        const subjectConf = select('//saml:SubjectConfirmation', doc)[0];
        subjectConf.getAttribute('Method').should.equal('urn:oasis:names:tc:SAML:2.0:cm:bearer');
        subjectConf.removeAttribute('Method');
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors[0].should.have.string('subject confirmation method must be bearer');
        }
      });
    });

    describe('Response:Assertion:Subject:SubjectConfirmation:SubjectConfirmationData element', function () {
      it("must contain 'Recipient', 'NotOnOrAfter', and 'InResponseTo' attributes when using a high-security configuration", async function () {
        const doc = await parse(await buildValidResponse());
        const subjectConf = select('//saml:SubjectConfirmationData', doc)[0];
        subjectConf.removeAttribute('Recipient');
        subjectConf.removeAttribute('NotOnOrAfter');
        subjectConf.removeAttribute('InResponseTo');
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors.length.should.equal(3);
          err.errors.join('').should.have.string('Recipient is required');
          err.errors.join('').should.have.string('NotOnOrAfter is required');
          err.errors.join('').should.have.string('InResponseTo is required');
        }
      });

      it("must be rejected if the 'Recipient' attribute does not match one of the SP's ACS endpoints", async function () {
        const doc = await parse(await buildValidResponse());
        const subjectConf = select('//saml:SubjectConfirmationData', doc)[0];
        subjectConf.setAttribute('Recipient', 'https://google.com');
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors.length.should.equal(1);
          err.errors.join('').should.have.string('Recipient is not valid');
        }
      });

      it("must be rejected if the 'NotOnOrAfter' attribute reflects a date matching or prior to the current instant", async function () {
        const doc = await parse(await buildValidResponse());
        const subjectConf = select('//saml:SubjectConfirmationData', doc)[0];
        subjectConf.setAttribute('NotOnOrAfter', new Date().toISOString());
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors.length.should.equal(1);
          err.errors.join('').should.have.string('NotOnOrAfter is in the past');
        }
      });

      it("must be rejected if the 'InResponseTo' does not correspond to an AuthnRequest's ID", async function () {
        const doc = await parse(await buildValidResponse());
        const subjectConf = select('//saml:SubjectConfirmationData', doc)[0];
        subjectConf.setAttribute('InResponseTo', '-1');
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors.length.should.equal(1);
          err.errors.join('').should.have.string('InResponseTo is not valid');
        }
      });
    });

    describe('Response:Assertion:Conditions element', function () {
      it("must be rejected if it contains a 'NotBefore' date in the future", async function () {
        const doc = await parse(await buildValidResponse());
        const conditions = select('//saml:Conditions', doc)[0];
        const newDate = new Date();
        newDate.setYear('3030');
        conditions.setAttribute('NotBefore', newDate.toISOString());
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors.length.should.equal(1);
          err.errors.join('').should.have.string('NotBefore is in the future');
        }
      });

      it("must be rejected if it contains a 'NotOnOrAfter' date in the past", async function () {
        const doc = await parse(await buildValidResponse());
        const conditions = select('//saml:Conditions', doc)[0];
        const newDate = new Date();
        newDate.setYear('2000');
        conditions.setAttribute('NotOnOrAfter', newDate.toISOString());
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors.length.should.equal(1);
          err.errors.join('').should.have.string('NotOnOrAfter is in the past');
        }
      });
    });

    describe('Response:Assertion:Conditions:AudienceRestriction element', function () {
      it("must be rejected if it does not contain an 'Audience' element matching the SP's entity ID", async function () {
        const doc = await parse(await buildValidResponse());
        const audience = select('//saml:Conditions/saml:AudienceRestriction/saml:Audience', doc)[0];
        audience.textContent = 'google.com';
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors.length.should.equal(1);
          err.errors.join('').should.have.string('Audience does not match');
        }
      });

      it('should be ok if the entityID is just a string', async function () {
        const doc = await parse(await buildValidResponse());
        const audience = select('//saml:Conditions/saml:AudienceRestriction/saml:Audience', doc)[0];
        audience.textContent = sp.entityID;
        await consume(doc);
      });

      let _sp;
      let _idp;
      before(function () {
        _sp = sp;
        _idp = idp;
        sp = entityFixtures.simpleSPWithCredentialsAndURIEntityID;
        idp = entityFixtures.simpleIDPWithCredentialsAndURIEntityID;
      });
      after(function () {
        sp = _sp;
        idp = _idp;
      });

      it('should be ok if the entityIDs are different strings that resolve to the same URL', async function () {
        const doc = await parse(await buildValidResponse());
        await consume(doc);
      });
    });

    describe('Response:Assertion:AttributeStatement', function () {
      it('should be absent when not provided', async function () {
        const doc = await parse(await buildResponseWithoutAttributes());
        const attrStatement = select('//saml:AttributeStatement', doc)[0];
        assert.isUndefined(attrStatement);
      });
    });

    describe('Response:Assertion:AuthnStatement', function () {
      it('must be present', async function () {
        const doc = await parse(await buildValidResponse());
        const authnStatement = select('//saml:AuthnStatement', doc)[0];
        doc.removeChild(authnStatement);
        try {
          await consume(doc);
        } catch (err) {
          err.should.be.an.instanceof(ValidationError);
          err.errors.length.should.equal(1);
          err.errors.join('').should.have.string('Assertion must contain at least one AuthnStatement');
        }
      });
    });

    it('should pass validation when all of these conditions are met', async function () {
      const result = await consume(await parse(await buildValidResponse()));
      result.should.not.be.null;
      result.idp.should.not.be.null;
      result.nameID.should.not.be.null;
      result.nameIDFormat.should.not.be.null;
      result.attributes.length.should.equal(1);
    });

    it('should pass validation when attributes are not provided', async function () {
      const result = await consume(await parse(await buildResponseWithoutAttributes()));
      result.should.not.be.null;
      result.idp.should.not.be.null;
      result.nameID.should.not.be.null;
      result.nameIDFormat.should.not.be.null;
      result.attributes.length.should.equal(0);
    });
  });
});
