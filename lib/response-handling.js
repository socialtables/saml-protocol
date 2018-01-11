import { DOMParser, XMLSerializer } from 'xmldom';
import xpath from 'xpath';

import { getCredentialsFromEntity } from './util/credentials';
import { decryptAssertion } from './util/encryption';
import { ProtocolError, ValidationError, RejectionError } from './errors';
import namespaces from './namespaces';
import protocol from './protocol';
import ResponseValidator from './response-validation';

const select = xpath.useNamespaces(namespaces);

/**
 * Entrypoint for assertion processing - takes an SAML assertion
 * and returns a description of it's contents if the everything checks
 * out.
 * @param model: model for IDP and request lookup
 * @param sp: Service Provider config object
 * @param samlResponse: SAML response passed from protocol layer
 * @returns: a description of the nameID and claims in the response
 * @throws: errors in case of failure
 */
async function processResponse(model, sp, samlResponse) {
  // decode and parse the SAML document
  let doc = new DOMParser().parseFromString(samlResponse.payload);

  // choose the first Issuer node from the document, which
  // should reflect the assertion's IDP
  const issuer = select('//saml:Issuer/text()', doc)[0];
  if (!issuer) {
    throw new ProtocolError(
      'Unable to identify issuer',
      sp,
      null,
      samlResponse.payload,
    );
  }

  let idp;
  try {
    // look up IDP corresponding to this response
    idp = await model.getIdentityProvider(issuer.nodeValue);
  } catch (error) {
    throw new ProtocolError(
      `Unable to identify IDP: ${error}`,
      sp,
      null,
      samlResponse.payload,
    );
  }

  const validator = new ResponseValidator(sp, idp, model);
  // ensure status is success; rejection error thrown otherwise
  checkStatus(doc, idp);

  if (samlResponse.verifySignature) {
    // the REDIRECT protocol binding uses query-level signatures,
    // so invoke the protocol level check if supported.
    validator.hasValidSignature = samlResponse.verifySignature(idp);
  } else {
    // for POST responses, the signature may be in the top-level
    // Response, or it may be inside the Assertion, which may be
    // encrypted. validate all unencrypted signatures now.
    validator.validateAllSignatures(samlResponse.payload, doc);
  }

  let assertion;

  // next, decrypt the assertion if necessary
  if (select('//saml:EncryptedAssertion', doc).length) {
    // remove the top-level signature, as it is now invalid
    select('//ds:Signature', doc).forEach((sigNode) => {
      doc.removeChild(sigNode);
    });

    // encryption creds are provided by the SP
    const encryptCreds = getCredentialsFromEntity(sp, 'encryption');
    doc = await decryptAssertion(doc, encryptCreds);

    assertion = select('//saml:Assertion', doc)[0];

    const newDocXML = new XMLSerializer().serializeToString(doc);
    validator.validateAllSignatures(newDocXML, assertion);
  } else {
    assertion = select('//saml:Assertion', doc)[0];
  }

  // do conditions and protocol validations
  validator.validateSignatureRequirement();
  await validator.validateResponseDocument(doc);
  // throw an error with the aggregate validation issues if necessary
  if (!validator.isValid()) {
    throw new ValidationError(
      'invalid assertion',
      validator.getErrors(),
      sp,
      idp,
      samlResponse.payload,
    );
  }

  // if possible, make the request ID as processed to avoid playback attacks
  if (model.invalidateRequestID) {
    await model.invalidateRequestID(validator.inResponseTo, idp);
  }

  // prepare and return assertion payload descriptor
  const nameIDNode = select('//saml:Subject/saml:NameID', assertion)[0];
  const nameID = select('./text()', nameIDNode)[0].nodeValue;
  const nameIDFormat = nameIDNode.getAttribute('Format') || protocol.NAMEIDFORMAT.undefined;
  return {
    idp,
    nameID,
    nameIDFormat,
    attributes: extractUserAttributes(assertion),
  };
}

/**
 * Checks for failure messages from the IDP, throws accordingly
 * @param doc: document
 * @param idp: identity provider config
 */
function checkStatus(doc, idp) {
  const statusNode = select('//samlp:StatusCode', doc)[0];
  const statusCodeAttr = statusNode.getAttribute('Value');
  const statusCodeMatch = statusCodeAttr.match(/urn:oasis:names:tc:SAML:2.0:status:(.*)/);

  // Success status means all good
  if (statusCodeMatch[1] === 'Success') {
    return statusCodeMatch[1];
  } // otherwise, we won't be able to proceed
  const messageNodes = select('//samlp:StatusMessage/text()', doc);
  const messageStrings = messageNodes.map(node => node.nodeValue);

  let errBody = `IDP rejected AuthnRequest with status: ${statusCodeMatch[1]}`;
  if (messageStrings.length) {
    errBody += ` and messages: ${messageStrings.join(', ')}`;
  }

  const serializedDoc = new XMLSerializer().serializeToString(doc);
  throw new RejectionError(errBody, null, idp, serializedDoc);
}

/**
 * Extracts usable user attributes from a given assertion.
 * @param assertion: SAML assertion
 * @return: a list of attribute descriptor objects
 */
function extractUserAttributes(assertion) {
  const attributeStatement = select('//saml:AttributeStatement', assertion)[0];

  if (attributeStatement) {
    const attributes = select('saml:Attribute', attributeStatement);

    return attributes.map((attrNode) => {
      const attrName = attrNode.getAttribute('Name');
      const friendlyName = attrNode.getAttribute('FriendlyName');
      const attrVals = select('saml:AttributeValue/text()', attrNode)
        .map(n => n.nodeValue)
        .filter(n => n);

      return {
        name: attrName,
        friendlyName,
        values: attrVals,
      };
    });
  }
  // attribute statement is not required, try falling back to nameId
  return [];
}

/**
 * User attribute mapper - optional processing phase which maps
 * IDP-produced attributes to service-provider user fields based on a provided
 * attribute map. Helps to simplify service-provider usage pattern.
 * @param attributes: array of attribute descriptors
 * @param attributeMapping: attribute mapping to use
 * @return: mapped attributes in an object
 */
function mapUserAttributes(attributes, attributeMapping) {
  const invertedAttributeMap = attributeMapping
    .reduce((map, key) => {
      const sources = attributeMapping[key];
      sources.forEach((source) => {
        map[source] = key;
      });
      return map;
    }, {});

  return attributes.reduce((result, attribute) => {
    let destKey = invertedAttributeMap[attribute.name.toLowerCase()];
    if (!destKey) {
      if (attribute.friendlyName) {
        destKey = invertedAttributeMap[attribute.friendlyName.toLowerCase()];
      }
    }
    if (destKey) {
      let attrVal = attribute.values;
      if (attrVal.length < 2) {
        ([attrVal] = attrVal);
      }
      result[destKey] = attrVal;
    }
    return result;
  }, {});
}

export {
  // methods used by rest of app
  processResponse,
  mapUserAttributes,

  // internals exposed for testing
  checkStatus,
  extractUserAttributes,
};
