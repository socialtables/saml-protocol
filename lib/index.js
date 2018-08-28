import errors from './errors';
import {
  buildSPMetadata,
  getIDPFromMetadata,
  buildIDPMetadata,
  getSPFromMetadata,
} from './metadata';
import { createBoundAuthnRequest } from './request-construction';
import { processAuthnRequest } from './request-handling';
import { buildBoundAuthnFailureResponse, buildBoundSuccessResponse } from './response-construction';
import { processResponse } from './response-handling';
import { getDataFromPostBinding, getDataFromRedirectBinding } from './protocol-bindings';

class ServiceProvider {
  constructor(config, model) {
    this.sp = {
      requireSignedResponses: false,
      endpoints: {},
      extendedRequirements: {},
      ...config,
    };
    this.model = model;
  }

  produceAuthnRequest(idp, options) {
    return createBoundAuthnRequest(this.sp, idp, this.model, options);
  }

  consumePostResponse(formParams) {
    const response = getDataFromPostBinding(formParams);
    return processResponse(this.model, this.sp, response);
  }

  consumeRedirectResponse(queryParams) {
    const response = getDataFromRedirectBinding(queryParams);
    return processResponse(this.model, this.sp, response);
  }

  produceSPMetadata(shouldSign) {
    return buildSPMetadata(this.sp, (shouldSign === undefined) ? true : shouldSign);
  }

  getIDPFromMetadata(xml) { // eslint-disable-line
    return getIDPFromMetadata(xml);
  }
}

class IdentityProvider {
  constructor(config, model) {
    this.idp = {
      requireSignedRequests: false,
      responseLatencyInSecs: 0,
      endpoints: {},
      ...config,
    };
    this.model = model;
  }

  consumePostAuthnRequest(formParams) {
    const request = getDataFromPostBinding(formParams);
    return processAuthnRequest(this.model, this.idp, request);
  }

  consumeRedirectAuthnRequest(queryParams) {
    const request = getDataFromRedirectBinding(queryParams);
    return processAuthnRequest(this.model, this.idp, request);
  }

  produceSuccessResponse(sp, inResponseTo, nameID, attributes) {
    return buildBoundSuccessResponse(sp, this.idp, this.model, inResponseTo, nameID, attributes);
  }

  produceFailureResponse(sp, inResponseTo, errorMessage) {
    return buildBoundAuthnFailureResponse(sp, this.idp, this.model, inResponseTo, errorMessage);
  }

  produceIDPMetadata(shouldSign) {
    return buildIDPMetadata(this.idp, (shouldSign === undefined) ? true : shouldSign);
  }

  getSPFromMetadata(xml) { // eslint-disable-line
    return getSPFromMetadata(xml);
  }
}

export {
  ServiceProvider,
  IdentityProvider,
  errors,
};
