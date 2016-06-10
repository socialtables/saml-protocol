"use strict";

module.exports = SAMLModelStub;

function SAMLModelStub() {

	this.idpStub = {};
	this.spStub = {};
	this.reqIDStore = {};
	this.loginStore = {};

	this.getServiceProvider  = function(entityID) {  // IDP REQUIRED
		return Promise.resolve(this.spStub);
	};

	this.getIdentityProvider = function(entityID) {  // SP REQUIRED
		return Promise.resolve(this.idpStub);
	};

	this.storeRequestID = function(requestID, idp) {  // SP REQUIRED
		this.reqIDStore[requestID] = idp.entityID;
		return Promise.resolve();
	};

	this.verifyRequestID = function(requestID, idp) {  // SP REQUIRED
		if (this.reqIDStore[requestID] == idp.entityID) {
			return Promise.resolve();
		}
		else {
			return Promise.reject();
		}
	};

	this.invalidateRequestID = function(requestID, idp) { // SP OPTIONAL
		delete this.reqIDStore[requestID];
		return Promise.resolve();
	};

	this.getNow = function() {
		return this.now || new Date();
	};

	// General
	// getServiceProvider  (entityID)         IDP
	// getIdentityProvider (entityID)         SP

	// Single Sign On
	// storeRequestID  (entityID, requestID)  SP
	// verifyRequestID (entityID, requestID)  SP                    IDP, SP

	/*
	Planned for SLO support


	Single Logout
	saveLogin (entityID, nameID)           IDP
	getEntitiesWithLogin (nameID)          IDP, SP
	logout (nameID)

	this.saveLogin = function(entityID, nameID) { // IDP & SP OPTIONAL (SLO)
		this.loginStore[nameID] = this.loginStore[nameID] || [];
		this.loginStore[nameID].push(entityID);
		return Promise.resolve();
	};

	this.getEntitiesWithLogin = function(nameID) { // IDP & SP OPTIONAL (SLO)
		return Promise.resolve(this.loginStore[nameID] || []);
	};

	this.logout = function(nameID) { // IDP & SP OPTIONAL (SLO)
		delete this.loginStore[nameID];
		return Promise.resolve();
	};
	*/
};

SAMLModelStub.whichResolvesSP = function(sp) {
	const stub = new SAMLModelStub();
	stub.spStub = sp;
	return stub;
};

SAMLModelStub.whichResolvesIDP = function(idp) {
	const stub = new SAMLModelStub();
	stub.idpStub = idp;
	return stub;
};

SAMLModelStub.prototype.validateLikeIts = function(targetDate) {
	this.date = targetDate;
};
