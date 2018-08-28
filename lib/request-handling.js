/*
eslint-disable import/prefer-default-export
*/

import { DOMParser } from 'xmldom';
import xpath from 'xpath';

import protocol from './protocol';
import { ProtocolError, ValidationError } from './errors';
import namespaces from './namespaces';
import { getCredentialsFromEntity } from './util/credentials';
import { validateXMLSignature } from './util/signing';

const select = xpath.useNamespaces(namespaces);

/**
 * Entrypoint for authentication request processing - takes an SAML request
 * and returns a description of the requesting servide provider and other
 * request data.
 * @param model: model for SP lookup
 * @param idp: Identity Provider config object
 * @param samlRequest: SAML request passed from protocol layer
 * @returns: a description of the data in the request
 * @throws: errors in case of failure
 */
async function processAuthnRequest(model, idp, samlRequest) {
  // decode and parse the SAML document
  const doc = new DOMParser().parseFromString(samlRequest.payload);

  // choose the first Issuer node from the document, which
  // should reflect the assertion's IDP
  const issuer = select('//saml:Issuer/text()', doc)[0];
  if (!issuer) {
    throw new ProtocolError('Unable to identify issuer');
  }

  let sp;
  try {
    // look up SP corresponding to this response
    sp = await model.getServiceProvider(issuer.nodeValue);
  } catch (error) {
    throw new ProtocolError('Unable to identify SP', error);
  }
  let hasValidSignature;

  if (samlRequest.verifySignature) {
    // validate redirect binding signatures
    hasValidSignature = samlRequest.verifySignature(idp);
  } else {
    // validate post binding signatures
    const signatures = select('//ds:Signature', doc);
    const creds = getCredentialsFromEntity(sp, 'signing');

    // validate all the sigs - there are edge cases where we have more than one!
    signatures.forEach((sig) => {
      creds.forEach((credential) => {
        const validationErrors = validateXMLSignature(samlRequest.payload, sig, credential);
        if (!validationErrors) {
          hasValidSignature = true;
        }
      });
    });
  }

  // throw error if sig check fails
  if (!hasValidSignature && idp.requireSignedRequests) {
    throw new ValidationError('IDP requires authentication requests to be signed.');
  }

  const authnRequestNode = select('//samlp:AuthnRequest', doc)[0];

  // start building request
  const requestObj = {
    idp,
    sp,
    isPassive: !!authnRequestNode.getAttribute('IsPassive'),
    forceAuthn: !!authnRequestNode.getAttribute('ForceAuthn'),
    requestID: authnRequestNode.getAttribute('ID'),
  };

  // attach nameID policy if specified
  const nameIDPolicyNode = select('//samlp:NameIDPolicy', doc)[0];
  if (nameIDPolicyNode) {
    requestObj.nameID = {
      format: nameIDPolicyNode.getAttribute('Format'),
      allowCreate: nameIDPolicyNode.getAttribute('AllowCreate'),
    };
  }

  // attach requested authentication classes
  const requestedAuthnContextNode = select('//samlp:RequestedAuthnContext', doc)[0];
  if (requestedAuthnContextNode) {
    requestObj.authnContextClassComparison = requestedAuthnContextNode.getAttribute('Comparison') || protocol.AUTHNCONTEXTCOMPARISON.EXACT;
    requestObj.authnContextClasses = select('//saml:AuthnContextClassRef/text()', requestedAuthnContextNode).map(n => n.nodeValue);
  }

  return requestObj;
}

export {
  // methods used by rest of app
  processAuthnRequest,
};
