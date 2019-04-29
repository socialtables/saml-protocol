import { expect, should } from 'chai';
import xpath from 'xpath';
import { DOMParser } from 'xmldom';

import * as metadata from '../lib/metadata';
import entityFixtures from './fixtures/entities';

should();

describe('Metadata creation and ingestion functions', () => {
  describe('buildIDPMetadata', () => {
    const { simpleIDP, simpleIDPWithCredentials: idpWithCredentials } = entityFixtures;

    it('should describe a simple IDP as valid XML', () => {
      const xml = metadata.buildIDPMetadata(simpleIDP);
      const node = new DOMParser().parseFromString(xml);
      xml.should.not.be.null;
      node.should.not.be.null;

      xpath.select("//*[local-name(.)='IDPSSODescriptor']", node)
        .length.should.equal(1);
      xpath.select("//*[local-name(.)='SingleSignOnService']", node)
        .length.should.equal(2);
    });

    it('should describe an IDP with credentials appropreately', () => {
      const xml = metadata.buildIDPMetadata(idpWithCredentials);
      const node = new DOMParser().parseFromString(xml);
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

  describe('buildIDPMetadata and getIDPFromMetadata', () => {
    it('Should get an IDP config matching the supplied IDP as a result of ingesting metadata', () => {
      const idp = entityFixtures.simpleIDPWithCredentials;
      idp.requireSignedRequests = true;

      const encoded = metadata.buildIDPMetadata(idp);
      const decoded = metadata.getIDPFromMetadata(encoded);

      decoded.should.not.be.null;
      decoded.entityID.should.equal(idp.entityID);
      decoded.endpoints.login.post.should.equal(idp.endpoints.login);
      decoded.endpoints.login.redirect.should.equal(idp.endpoints.login);
      decoded.credentials.should.not.be.null;
      decoded.credentials[0].certificate.should.not.be.null;
      decoded.credentials[0].certificate.should.equal(idp.credentials[0].certificate); // TODO: fix brittle string comp
      expect(decoded.requireSignedRequests).to.be.ok;
    });
  });

  describe('buildSPMetadata', () => {
    const { simpleSP, simpleSPWithCredentials: spWithCredentials } = entityFixtures;

    it('should describe a simple SP as valid XML', () => {
      const xml = metadata.buildSPMetadata(simpleSP);
      const node = new DOMParser().parseFromString(xml);
      xml.should.not.be.null;
      node.should.not.be.null;

      xpath.select("//*[local-name(.)='SPSSODescriptor']", node)
        .length.should.equal(1);
      xpath.select("//*[local-name(.)='AssertionConsumerService']", node)
        .length.should.equal(2);
    });

    it('should describe an SP with credentials appropreately', () => {
      const xml = metadata.buildSPMetadata(spWithCredentials);
      const node = new DOMParser().parseFromString(xml);
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

  describe('buildSPMetadata and getSPFromMetadata', () => {
    it('Should get an SP config matching the supplied SP as a result of ingesting metadata', () => {
      const sp = entityFixtures.simpleSPWithCredentials;

      const encoded = metadata.buildSPMetadata(sp);
      const decoded = metadata.getSPFromMetadata(encoded);

      decoded.should.not.be.null;
      decoded.entityID.should.equal(sp.entityID);
      decoded.endpoints.assert.post.should.equal(sp.endpoints.assert);
      decoded.endpoints.assert.redirect.should.equal(sp.endpoints.assert);
      decoded.credentials.should.not.be.null;
      decoded.credentials[0].certificate.should.not.be.null;
      decoded.credentials[0].certificate.should.equal(sp.credentials[0].certificate); // TODO: fix brittle string comp
      expect(decoded.requireSignedResponses).to.be.ok;
    });
  });
});
