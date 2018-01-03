import xpath from 'xpath';
import { DOMParser, XMLSerializer } from 'xmldom';
import xmlenc from 'xml-encryption';
import { promisify } from 'util';
import { getPublicKeyFromCertificate } from './credentials';
import { addPEMHeaders } from './pem-formatting';
import namespaces from '../namespaces';

const select = xpath.useNamespaces(namespaces);

// these are the encryption algorithms supported by xml-encryption
const supportedAlgorithms = {
  encryption: [
    'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
    'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
  ],
  keyEncryption: [
    'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
  ],
};

const defaultAlgorithms = {
  encryption: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  keyEncryption: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
};

/**
 * Mutates a SAML document, converting an EncryptedAssertion into an Assertion
 * if one is present.
 * @param doc: XML document to operate upon
 * @param credential: an array of credential objects containing private keys
 */
async function decryptAssertion(doc, credentials) {
  const encryptedAssertion = select('//saml:EncryptedAssertion', doc)[0];

  // bail if there's nothing to do
  if (!encryptedAssertion) {
    return doc;
  }

  // find and the encrypted data node - xmlenc can accept this directly
  const encryptedDataNode = select("//*[local-name(.)='EncryptedData']", encryptedAssertion)[0];
  const encryptedDataStr = new XMLSerializer().serializeToString(encryptedDataNode);

  // decrypt the XML - this will be a string
  const decryptedXml = await decryptData(encryptedDataStr, credentials);
  // deserialize the assertion and mutate the document
  const newAssertionDoc = new DOMParser().parseFromString(decryptedXml, namespaces.saml);
  const assertion = select("//*[local-name(.)='Assertion']", newAssertionDoc)[0];
  encryptedAssertion.parentNode.replaceChild(assertion, encryptedAssertion);

  // we have to do another serialize/deserialize pass to get the
  // subdocument to respect the parent's namespaces
  const newDocXML = new XMLSerializer().serializeToString(doc);
  const newDoc = new DOMParser().parseFromString(newDocXML);
  return newDoc;
}

/**
 * Mutates a SAML document, converting an Assertion into an EncryptedAssertion.
 * @param doc: an SAML document
 * @param credential: a credential object containing a public_key and certificate
 * @param alogrithms: optional specifier to set encryption algorithms
 */
async function encryptAssertion(doc, credential, algorithms) {
  // get the assertion body (there can only be one) as a string.
  const assertion = select('//saml:Assertion', doc)[0];
  const assertXml = new XMLSerializer().serializeToString(assertion);

  // encrypt the XML payload
  const encryptedData = await encryptData(assertXml, credential, algorithms);

  // cobble together the EncryptedAssertion node as a string and parse
  const encTagName = 'saml:EncryptedAssertion';
  const encAssertString = `<${encTagName}>${encryptedData}</${encTagName}>`;
  const encryptedAssertion = new DOMParser().parseFromString(encAssertString);

  // replace the assertion with the encrypted node
  doc.replaceChild(encryptedAssertion, assertion);

  return doc;
}

/**
 * @param encryptedData: encrypted XML node
 * @param credential: array of credentials containing private keys
 * @return a promise of decrypted data
 */
async function decryptData(encryptedData, credentials) {
  for (const credential of credentials) {
    const decryptOptions = { key: credential.privateKey };
    try {
      const decryptedData = await promisify(xmlenc.decrypt)(encryptedData, decryptOptions);
      return decryptedData;
    } catch (error) {}
  }
  throw new Error('No decryption credentials');
}

/**
 * @param data: XML node to encrypt
 * @param credential: credential to use for encryption - may optionally
 * include a publicKey attribute, but will infer one from the certificate
 * attribute otherwise.
 * @param algorithms: optional specifier to set algorithms
 * @return a promise of encrypted data
 */
function encryptData(data, credential, {
  encryption = defaultAlgorithms.encryption,
  keyEncryption = defaultAlgorithms.keyEncryption,
} = {}) {
  // ensure PEM headers are present on the credential
  const certificate = addPEMHeaders('CERTIFICATE', credential.certificate);

  // resolve public key
  let { publicKey } = credential;
  if (!publicKey) { // only invoke if publicKey attribute is not present for performance
    publicKey = getPublicKeyFromCertificate(certificate);
  }

  const encryptOptions = {
    encryptionAlgorithm: encryption,
    // xmlenc's API spells this this way :(
    keyEncryptionAlgorighm: keyEncryption,
    pem: certificate,
    rsa_pub: publicKey,
  };
  return promisify(xmlenc.encrypt)(data, encryptOptions);
}

export {
  decryptAssertion,
  encryptAssertion,
  decryptData,
  encryptData,
  supportedAlgorithms,
};
