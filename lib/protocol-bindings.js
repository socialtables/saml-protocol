import { URL, URLSearchParams } from 'url';
import zlib from 'zlib';

import { getCredentialsFromEntity } from './util/credentials';
import { signXML, chooseSignatureAlgorithm, createURLSignature, verifyURLSignature } from './util/signing';
import protocol from './protocol';


// ///////////////////////////////////////////////////////////////
// // POST and REDIRECT SAML protocol binding implementations ////
// ///////////////////////////////////////////////////////////////

// protocol bindings (REDIRECT and POST)

/**
 * Expands abbreviated config bindings for easier lookup
 * @param endpoints: endpoints object from entity config
 * @return an expanded endpoint.thing.httpMethod object
 */
function expandBindings(endpoints) {
  return Object.keys(endpoints).reduce((expanded, method) => {
    const bindingDefinition = endpoints[method];
    if (typeof bindingDefinition === 'object') {
      expanded[method] = bindingDefinition;
    } else {
      expanded[method] = {
        post: bindingDefinition,
        redirect: bindingDefinition,
      };
    }
    return expanded;
  }, {});
}

function chooseBinding(recipient, action) {
  const endpoints = expandBindings(recipient.endpoints);
  const definedBindings = endpoints[action];
  if (!definedBindings) {
    throw new Error('Recipient entity has no suitable endpoints');
  }
  const defaultBinding = definedBindings._default || 'post';
  let chosenBinding = defaultBinding;
  if (!definedBindings[chosenBinding]) {
    chosenBinding = (chosenBinding === 'post') ? 'redirect' : 'post';
  }
  return {
    binding: chosenBinding,
    url: definedBindings[chosenBinding],
    longformURI: (chosenBinding === 'post') ? protocol.BINDINGS.POST : protocol.BINDINGS.REDIRECT,
  };
}

/**
 * Chooses and applies a protocol binding for a given payload. Favors post
 * when both are defined since it is more versitile.
 * @param sender: sender entity
 * @param recipient: recieving entity
 * @param xmlPayload: XML payload to deliver
 * @param isResponse: whether this is a response (or a request if falsey)
 * @param action: the action (such as "assert" or "login")
 * @param choice: binding choice produced by chooseBinding
 * @return: an object indicating what to do the user's browser
 */
function applyBinding(sender, recipient, xmlPayload, isResponse, action, choice) {
  // apply the chosen binding, return result
  if (choice.binding === 'post') {
    return applyPostBinding(
      sender,
      recipient,
      xmlPayload,
      isResponse,
      choice.url,
      action,
    );
  }

  return applyRedirectBinding(
    sender,
    recipient,
    xmlPayload,
    isResponse,
    choice.url,
  );
}

/**
 * Applies the GET / redirect authentication request binding to a given
 * AuthnRequest, and returns a description of where to send the user
 */
function applyRedirectBinding(sender, recipient, xmlPayload, isResponse, endpointURL) {
  // deflate and base64 the payload
  const samlPayload = zlib.deflateRawSync(xmlPayload).toString('base64');

  const queryKey = isResponse ? 'SAMLResponse' : 'SAMLRequest';
  const relayState = '';

  const url = new URL(endpointURL);
  url.searchParams.set(queryKey, samlPayload);
  if (relayState && relayState.length) {
    url.searchParams.set('RelayState', relayState);
  }

  if (
    (sender.signAllResponses || sender.signAllRequests) ||
    (recipient.requireSignedResponses || recipient.requireSignedRequests)
  ) {
    const sigAlg = chooseSignatureAlgorithm([sender, recipient]);
    const sigCredential = getCredentialsFromEntity(sender, 'signing')[0];
    if (!sigCredential || !(sigCredential.privateKey && sigCredential.certificate)) {
      throw new Error('Unable to apply redirect binding - no signing credential provided');
    }

    url.searchParams.set('SigAlg', sigAlg);
    const signedPayload = constructSignaturePayload(url.searchParams);
    const signature = createURLSignature(sigCredential.privateKey, signedPayload, sigAlg);

    // apply query parameters
    url.searchParams.set('SigAlg', sigAlg);
    url.searchParams.set('Signature', signature);
  }

  // construct and return redirect descriptor
  return {
    method: 'GET',
    url,
  };
}

/**
 * Applies the POST binding to a given Response, and returns a descirption
 * of where to send the user
 */
function applyPostBinding(sender, recipient, xmlPayload, isResponse, endpointURL, action) {
  let finalPayload = xmlPayload;

  // if we should sign the request based on configuration, do so
  if (
    (sender.signAllResponses || sender.signAllRequests) ||
    (recipient.requireSignedResponses || recipient.requireSignedRequests)
  ) {
    const sigAlg = chooseSignatureAlgorithm([sender, recipient]);
    const sigCredential = getCredentialsFromEntity(sender, 'signing')[0];

    if (!sigCredential) {
      throw new Error('No usable signing credential for sender');
    }

    // sign the request
    const tagName = {
      login: 'AuthnRequest',
      assert: 'Response',
    }[action];

    finalPayload = signXML(
      xmlPayload,
      {
        reference: `//*[local-name(.)='${tagName}']/*[local-name(.)='Issuer']`,
        action: 'after',
      },
      `//*[local-name(.)='${tagName}']`,
      sigCredential,
      { signatureAlgorithm: sigAlg },
    );
  }

  // base64 encode the payload
  const base64ed = Buffer.from(finalPayload, 'utf8').toString('base64');

  const url = new URL(endpointURL);
  const bodyParams = {};
  const bodyKey = isResponse ? 'SAMLResponse' : 'SAMLRequest';
  bodyParams[bodyKey] = base64ed;

  return {
    method: 'POST',
    contentType: 'x-www-form-urlencoded',
    formBody: bodyParams,
    url,
  };
}

function getDataFromRedirectBinding(queryParams) {
  const samlParamName = queryParams.get('SAMLRequest') ? 'SAMLRequest' : 'SAMLResponse';
  const samlPayload = queryParams.get(samlParamName);
  if (!samlPayload) {
    throw new Error(`Invalid ${samlParamName}`);
  }

  let verifySignature = null;
  const signature = queryParams.get('Signature');
  if (signature) {
    const signedPayload = constructSignaturePayload(queryParams);
    const sigAlg = queryParams.get('SigAlg');

    verifySignature = (sender) => {
      const signingCredentials = getCredentialsFromEntity(sender, 'signing');

      return signingCredentials.some(credential => verifyURLSignature(
        credential.certificate,
        signedPayload,
        sigAlg,
        signature,
      ));
    };
  }

  return {
    payload: decodeXMLPayload(samlPayload),
    binding: 'redirect',
    isResponse: (samlParamName === 'SAMLResponse'),
    verifySignature,
  };
}

function getDataFromPostBinding(postParams) {
  const samlParamName = postParams.SAMLRequest ? 'SAMLRequest' : 'SAMLResponse';
  const samlPayload = postParams[samlParamName];
  if (!samlPayload) {
    throw new Error(`Invalid ${samlParamName}`);
  }

  return {
    payload: decodeXMLPayload(samlPayload),
    binding: 'post',
    isResponse: (samlParamName === 'SAMLResponse'),
  };
}

/**
 * Decodes an SAML payload, which will be base64ed and potentially deflated.
 * @return: decoded XML payload
 * @throws a fit if the payload isn't deflated or base64ed.
 */
function decodeXMLPayload(rawPayload) {
  const rawPayloadBuff = Buffer.from(rawPayload, 'base64');
  let decoded = null;

  // attempt to inflate with zlib
  try {
    decoded = zlib.inflateRawSync(rawPayloadBuff).toString('utf8');

    // if inflation failed, attempt raw conversion
    // if this fails, we have a legitimate error.
  } catch (err) {
    decoded = rawPayloadBuff.toString('utf8');
  }

  if (!decoded) {
    throw new Error('Unable to read SAMLResponse payload');
  } else {
    return decoded;
  }
}

/**
 * Constructs a query parameter string to sign
 */
function constructSignaturePayload(query) {
  const samlParamName = query.get('SAMLRequest') ? 'SAMLRequest' : 'SAMLResponse';

  const payload = new URLSearchParams();
  [samlParamName, 'RelayState', 'SigAlg']
    .filter(p => query.get(p))
    .forEach((p) => {
      payload.set(p, query.get(p));
    });
  return payload.toString();
}

export {
  expandBindings,
  chooseBinding,
  applyBinding,
  applyRedirectBinding,
  applyPostBinding,
  getDataFromRedirectBinding,
  getDataFromPostBinding,
  constructSignaturePayload,
};
