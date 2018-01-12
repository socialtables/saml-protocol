

import { should, expect } from 'chai';
import { IdentityProvider, ServiceProvider } from '../lib';
import { signXML } from '../lib/util/signing';
import entityFixtures from './fixtures/entities';
import credentialFixtures from './fixtures/credentials';
import ModelStub from './fixtures/model-stub';
import samlFixtures from './fixtures/saml';
import protocol from '../lib/protocol';

should();

describe('exports.IdentityProvider', () => {
  describe('consumePostAuthnRequest', () => {
    it('accepts an unsigned AuthnRequest encoded with a POST binding when signing is not required', async () => {
      const idp = new IdentityProvider(
        {
          ...entityFixtures.simpleIDPWithCredentials,
          requireSignedRequests: false,
        },
        ModelStub.whichResolvesSP(entityFixtures.oneloginSP),
      );

      const requestPayload = samlFixtures('onelogin/onelogin-saml-request.xml');
      const sampleRequestBase64 = Buffer.from(requestPayload, 'utf8').toString('base64');
      const formParams = { SAMLRequest: sampleRequestBase64 };

      const result = await idp.consumePostAuthnRequest(formParams);
      result.idp.entityID.should.equal(entityFixtures.simpleIDP.entityID);
      result.sp.entityID.should.equal(entityFixtures.oneloginSP.entityID);
      result.requestID.should.not.be.null;
      result.nameID.should.not.be.null;
    });

    it('rejects an unsigned AuthnRequest encoded with a POST binding when signing is required', async () => {
      const idp = new IdentityProvider(
        {
          ...entityFixtures.simpleIDPWithCredentials,
          requireSignedRequests: true,
        },
        ModelStub.whichResolvesSP(entityFixtures.oneloginSP),
      );

      const requestPayload = samlFixtures('onelogin/onelogin-saml-request.xml');
      const sampleRequestBase64 = Buffer.from(requestPayload, 'utf8').toString('base64');
      const formParams = { SAMLRequest: sampleRequestBase64 };

      try {
        await idp.consumePostAuthnRequest(formParams);
      } catch (error) {
        error.message.should.have.string('IDP requires authentication requests to be signed');
      }
    });

    it('accepts an AuthnRequest encoded with a POST binding with a valid signature when signing is required', async () => {
      const idp = new IdentityProvider(
        {
          ...entityFixtures.simpleIDPWithCredentials,
          requireSignedRequests: true,
        },
        ModelStub.whichResolvesSP({
          ...entityFixtures.oneloginSP,
          credentials: [credentialFixtures.sp1],
        }),
      );

      // the signed onelogin example request payload has an invalid digest,
      // possibly due to mangled line endings; instead, we sign their
      // unsigned example and use that.
      let requestPayload = samlFixtures('onelogin/onelogin-saml-request.xml');
      requestPayload = signXML(
        requestPayload,
        {
          reference: "//*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']",
          action: 'after',
        },
        "//*[local-name(.)='AuthnRequest']",
        credentialFixtures.sp1,
        { prefix: 'ds' },
      );

      const sampleRequestBase64 = Buffer.from(requestPayload, 'utf8').toString('base64');
      const formParams = { SAMLRequest: sampleRequestBase64 };
      const result = await idp.consumePostAuthnRequest(formParams);
      result.idp.entityID.should.equal(entityFixtures.simpleIDP.entityID);
      result.sp.entityID.should.equal(entityFixtures.oneloginSP.entityID);
      result.requestID.should.not.be.null;
      result.nameID.should.not.be.null;
    });

    describe('support consuming authn request parameters', function () {
      const spModel = new ModelStub();
      const idpModel = new ModelStub();

      const sp = new ServiceProvider(entityFixtures.simpleSPWithCredentials, spModel);
      const idp = new IdentityProvider(entityFixtures.simpleIDPWithCredentials, idpModel);


      const spMD = sp.produceSPMetadata();
      const idpMD = idp.produceIDPMetadata();

      spModel.idpStub = sp.getIDPFromMetadata(idpMD);
      idpModel.spStub = idp.getSPFromMetadata(spMD);

      it('can configure isPassive and forceAuth', async function () {
        const spRequestDescriptor = await sp.produceAuthnRequest(spModel.idpStub, { forceAuthn: true, isPassive: true });
        const idpRequestDescriptor = await idp.consumePostAuthnRequest(spRequestDescriptor.formBody);
        idpRequestDescriptor.forceAuthn.should.be.true;
        idpRequestDescriptor.isPassive.should.be.true;
      });

      it('should have optional authn context classes', async function () {
        const spRequestDescriptor = await sp.produceAuthnRequest(spModel.idpStub, { sendAuthnContext: false });
        const idpRequestDescriptor = await idp.consumePostAuthnRequest(spRequestDescriptor.formBody);
        expect(idpRequestDescriptor.authnContextClassComparison).to.be.undefined;
        expect(idpRequestDescriptor.authnContextClasses).to.be.undefined;
      });

      it('should be able to configure authn context classes and comparison', async function () {
        const authnContextClassComparison = protocol.AUTHNCONTEXTCOMPARISON.BETTER;
        const authnContextClasses = [protocol.AUTHNCONTEXT.PASSWORDPROTECTEDTRANSPORT, protocol.AUTHNCONTEXT.WINDOWS];
        const spRequestDescriptor = await sp.produceAuthnRequest(spModel.idpStub, {
          authnContextClassComparison,
          authnContextClasses,
        });
        const idpRequestDescriptor = await idp.consumePostAuthnRequest(spRequestDescriptor.formBody);
        idpRequestDescriptor.authnContextClassComparison.should.equal(authnContextClassComparison);
        idpRequestDescriptor.authnContextClasses.should.deep.equal(authnContextClasses);
      });
    });
  });
});
