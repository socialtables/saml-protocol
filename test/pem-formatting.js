import 'chai/register-should';
import * as pemFormatting from '../lib/util/pem-formatting';
import credentialFixtures from './fixtures/credentials';

describe('PEM formatting utilities', () => {
  const headersRe = /-----BEGIN [0-9A-Z ]+-----[^-]*-----END [0-9A-Z ]+-----/g;
  const certPem = credentialFixtures.idp1.certificate;

  before('cert fixture should not be null', () => {
    certPem.should.not.be.null;
  });

  describe('addPEMHeaders', () => {
    it('should correctly apply PEM headers to a certificate', () => {
      const strippedCertPem = pemFormatting.stripPEMHeaders(certPem);
      headersRe.test(strippedCertPem).should.not.be.ok;
      const reappliedCertPem = pemFormatting.addPEMHeaders('CERTIFICATE', strippedCertPem);
      headersRe.test(reappliedCertPem).should.be.ok;
    });
    it('should not add PEM headers to certificates that already possess them', () => {
      const reappliedCertPem = pemFormatting.addPEMHeaders('CERTIFICATE', certPem);
      reappliedCertPem.should.equal(certPem);
    });
  });

  describe('stripPEMHeaders', () => {
    let strippedCertPem;
    it('should correctly strip PEM headers from a certificate', () => {
      strippedCertPem = pemFormatting.stripPEMHeaders(certPem);
      strippedCertPem.should.not.be.null;
      headersRe.test(strippedCertPem).should.not.be.ok;
    });
    it('should allow pre-stripped PEM certitificates to pass through', () => {
      const doubleStripped = pemFormatting.stripPEMHeaders(strippedCertPem);
      doubleStripped.should.equal(strippedCertPem);
    });
  });
});
