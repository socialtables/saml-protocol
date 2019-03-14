class SamlError extends Error {
  constructor (message, sp, idp, payload) {
    super(message);

    this._sp = sp;
    this._idp = idp;
    this._payload = payload;
  }

  // add extended debug data in function bindings in case anyone's error
  // handler tries to serialize one of these.
  getSPn() {
    return this._sp;
  }

  getIDP () {
    return this._idp;
  }

  getPayload() {
    return this._payload;
  }
}

/**
 * Errors thrown when one or more conditions invalidated an assertion
 * or request. Groups an array of validation errors.
 */
class ValidationError extends SamlError {
  constructor (message, errors, sp, idp, payload) {
    super(message, sp, idp, payload);
    this.errors = errors || [message];
  }
}

/**
 * Errors thrown when an issue completely prevents the SAML protocol from
 * functioning - primairly entity configuration.
 */
class ProtocolError extends SamlError {}

/**
 * Thrown when an IDP rejects an auth request
 */
class RejectionError extends SamlError {}

export {
  ValidationError,
  ProtocolError,
  RejectionError,
};
