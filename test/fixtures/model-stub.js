class SAMLModelStub {
  constructor() {
    this.idpStub = {};
    this.spStub = {};
    this.reqIDStore = {};
    this.loginStore = {};
  }

  static whichResolvesSP(sp) {
    const stub = new SAMLModelStub();
    stub.spStub = sp;
    return stub;
  }

  static whichResolvesIDP(idp) {
    const stub = new SAMLModelStub();
    stub.idpStub = idp;
    return stub;
  }

  async getServiceProvider() { // IDP REQUIRED
    return this.spStub;
  }

  async getIdentityProvider() { // SP REQUIRED
    return this.idpStub;
  }

  async storeRequestID(requestID, idp) { // SP REQUIRED
    this.reqIDStore[requestID] = idp.entityID;
  }

  async verifyRequestID(requestID, idp) { // SP REQUIRED
    if (this.reqIDStore[requestID] !== idp.entityID) {
      throw new Error();
    }
  }

  async invalidateRequestID(requestID) { // SP OPTIONAL
    delete this.reqIDStore[requestID];
  }

  getNow() {
    return this.now || new Date();
  }

  validateLikeIts(targetDate) {
    this.date = targetDate;
  }

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
}

export default SAMLModelStub;
