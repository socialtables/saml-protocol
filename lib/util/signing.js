import { SignedXml } from 'xml-crypto';
import xmlbuilder from 'xmlbuilder';
import { stripPEMHeaders, addPEMHeaders } from './pem-formatting';

/**
 * KeyInfo provider class which wraps a certificate in a format accessible
 * to the xml-crypto library.
 * @param pem: key in PEM format with or without headers.
 */
class CertKeyInfo {
  constructor(pem) {
    // ensure pem is not a buffer
    this.pemString = pem.toString();
  }

  getKeyInfo(key, prefix) {
    const keyInfoXML = stripPEMHeaders(this.pemString);
    const element = {
      'ds:X509Data': {
        'ds:X509Certificate': keyInfoXML,
      },
    };
    if (prefix && prefix !== 'ds') {
      element['ds:X509Data'][`${prefix}:X509Certificate`] = element['ds:X509Data']['ds:X509Certificate'];
      delete element['ds:X509Data']['ds:X509Certificate'];
      element[`${prefix}:X509Data`] = element['ds:X509Data'];
      delete element['ds:X509Data'];
    }
    return xmlbuilder
      .begin()
      .ele(element)
      .end();
  }

  getKey() {
    return addPEMHeaders('CERTIFICATE', this.pemString);
  }
}

// we export this list for use in metadata
const supportedAlgorithms = [
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
];

// map node crypto shorthand signature algo names to their
// fully qualified URLs, and the URLs to themselves for
// easy reference.
const sigAlgLookup = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  'RSA-SHA1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
  'RSA-SHA256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  'RSA-SHA512': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  default: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
};

function resolveSignatureAlgorithm(sigAlg) {
  return sigAlgLookup[sigAlg] || sigAlgLookup.default;
}

/**
 * Creates a signature for use in query-param encoded GET requests.
 * xml-crypto already includes signing and verification logic, so
 * really we're just adding a level of algorithm name resolution and
 * payload formation.
 * @param privateKeyPem: private key in PEM format
 * @param signedPayload: payload string to sign
 */
function createURLSignature(privateKeyPem, signedPayload, sigAlg) {
  const privateKeyPemWithHeaders = addPEMHeaders('RSA PRIVATE KEY', privateKeyPem);
  const signingAlgorithmName = resolveSignatureAlgorithm(sigAlg);
  return SignedXml
    .prototype
    .findSignatureAlgorithm(signingAlgorithmName)
    .getSignature(signedPayload, privateKeyPemWithHeaders);
}

/**
 * Verifies a signature from a query-param encoded GET request.
 * xml-crypto already includes signing and verification logic, so
 * really we're just adding a level of algorithm name resolution and
 * payload formation.
 * @param certPem: certificate PEM
 * @param signedPayload: payload string on which to verify signature
 * @param signature: signature parameter
 */
function verifyURLSignature(certPem, signedPayload, sigAlg, signature) {
  const certPemWitHeaders = addPEMHeaders('CERTIFICATE', certPem);
  const signingAlgorithmName = resolveSignatureAlgorithm(sigAlg);
  return SignedXml
    .prototype
    .findSignatureAlgorithm(signingAlgorithmName)
    .verifySignature(signedPayload, certPemWitHeaders, signature);
}

/**
 * XML signature generator - signs an XML document at the specified location
 *
 * @param xml: raw XML document string to sign
 * @param signatureLocation: location in document to place signature
 * @param signedXPath: XPath of node to sign in document
 * @param credentials: object containing a certificate and private key (PEM)
 * @param options: options including 'prefix' and 'signatureAlgorithm'
 */
function signXML(xml, signatureLocation, signedXPath, credentials, options = {}) {
  // create and configure xml-crypto SignedXml instance
  const signatureAlgorithm = resolveSignatureAlgorithm(options.signatureAlgorithm);
  const signer = new SignedXml(null, { signatureAlgorithm });

  signer.keyInfoProvider = new CertKeyInfo(credentials.certificate);
  signer.signingKey = addPEMHeaders('RSA PRIVATE KEY', credentials.privateKey);

  signer.addReference(signedXPath, [
    'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
    'http://www.w3.org/2001/10/xml-exc-c14n#',
  ]);

  // compute signature and return signed XML document string
  signer.computeSignature(xml, {
    prefix: options.prefix || 'ds',
    location: signatureLocation || '',
  });

  return signer.getSignedXml();
}

/**
 * XML signature validatior - validates a single XML signature
 * @param xml: raw XML string containing the signature's referenced element
 * @param signatureNode: XML Signature node to validate
 * @param credential: object containing a certificate (PEM)
 * @return: 0 indicating success, or a list of validation errors
 */
function validateXMLSignature(xml, signatureNode, credential) {
  const sigCheck = new SignedXml();
  sigCheck.keyInfoProvider = new CertKeyInfo(credential.certificate);
  sigCheck.loadSignature(signatureNode);
  const isValid = sigCheck.checkSignature(xml);
  if (isValid) {
    return 0;
  }
  return sigCheck.validationErrors;
}

/**
 * Chooses a signature algorithm that both the IDP and SP support, using the
 * supported algorithm list (which is ordered by favorability).
 * @param parties: a list of parties which need to support the chosen algorithm.
 */
function chooseSignatureAlgorithm(parties) {
  let choices = supportedAlgorithms;
  parties.forEach((entity) => {
    if (entity.algorithms && entity.algorithms.signing) {
      choices = choices.filter(choice => entity.algorithms.signing.includes(choice));
    }
  });

  if (choices.length > 0) {
    return choices[0];
  }
  throw new Error('Unable to identify a signing algorithm supported by'
    + 'both the IDP and SP.');
}

export {
  createURLSignature,
  verifyURLSignature,
  signXML,
  validateXMLSignature,
  resolveSignatureAlgorithm,
  supportedAlgorithms,
  chooseSignatureAlgorithm,
};
