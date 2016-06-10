"use strict";

module.exports = {
	ValidationError,
	ProtocolError,
	RejectionError
};

/**
 * Errors thrown when one or more conditions invalidated an assertion
 * or request. Groups an array of validation errors.
 */
function ValidationError(message, errors, sp, idp, assertion) {

	Error.captureStackTrace(this);
	this.message = message;
	this.errors = errors || [message];

	// add extended debug data in function bindings in case anyone's error
	// handler tries to serialize one of these.
	this.getSP  = function() { return sp; };
	this.getIDP = function() { return idp; };
	this.getAssertion = function() { return assertion; };
}

/**
 * Errors thrown when an issue completely prevents the SAML protocol from
 * functioning - primairly entity configuration.
 */
function ProtocolError(message) {
	Error.captureStackTrace(this);
	this.message = message;
}

/**
 * Thrown when an IDP rejects an auth request
 */
function RejectionError(message) {
	Error.captureStackTrace(this);
	this.message = message;
}
