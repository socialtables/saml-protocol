"use strict";

const credentialFixtures = require("./credentials");

module.exports = {

	// IDPs
	simpleIDP: {
		entityID: "idp.test.com",
		credentials: [],
		endpoints: {
			login: {
				post: "idp.test.com/saml/login",
				redirect: "idp.test.com/saml/login"
			}
		},
		signAllResponses: false,
		requireSignedRequests: false
	},
	simpleIDPWithLatency: {
		entityID: "idp.test.com",
		credentials: [
			credentialFixtures.idp1
		],
		endpoints: {
			login: {
				post: "idp.test.com/saml/login",
				redirect: "idp.test.com/saml/login"
			}
		},
		signAllResponses: false,
		requireSignedRequests: false,
		responseLatencyInSecs: 2
	},
	simpleIDPWithCredentials: {
		entityID: "idp.test.com",
		credentials: [
			credentialFixtures.idp1
		],
		endpoints: {
			login: "idp.test.com/saml/login",
			logout: {
				post: "idp.test.com/saml/logout"
			}
		},
		nameIDFormats: [
			"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
		],
		signAllResponses: true,
		requireSignedRequests: false
	},

	simpleIDPWithCredentialsAndURIEntityID: {
		entityID: "https://entityuri-idp.test.com",
		credentials: [
			credentialFixtures.idp1
		],
		endpoints: {
			login: "https://entityuri-idp.test.com/saml/login",
			logout: {
				post: "https://entityuri-idp.test.com/saml/logout"
			}
		},
		nameIDFormats: [
			"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
		],
		signAllResponses: true,
		requireSignedRequests: false
	},

	// SPs
	simpleSP: {
		entityID: "sp.test.com",
		credentials: [],
		endpoints: {
			assert: "sp.test.com/assert"
		},
		signAllRequests: false,
		requireSignedResponses: false
	},
	simpleSPWithCredentials: {
		entityID: "sp.test.com",
		credentials: [
			credentialFixtures.sp1,
			credentialFixtures.sp2
		],
		endpoints: {
			assert: "sp.test.com/assert"
		},
		signAllRequests: true,
		requireSignedResponses: true,
		extendedRequirements: {
			InResponseTo: true,
			NotOnOrAfter: true,
			Recipient: true
		}
	},
	simpleSPWithCredentialsAndURIEntityID: {
		entityID: "https://entityuri-idp.test.com",
		credentials: [
			credentialFixtures.sp1,
			credentialFixtures.sp2
		],
		endpoints: {
			assert: "https://entityuri-idp.test.com/assert"
		},
		signAllRequests: true,
		requireSignedResponses: true,
		extendedRequirements: {
			InResponseTo: true,
			NotOnOrAfter: true,
			Recipient: true
		}
	},
	oneloginSP: {
		entityID: "http://sp.example.com/demo1/metadata.php",
		credentials: [
			credentialFixtures.sp1
		],
		endpoints: {
			assert: "http://sp.example.com/demo1/index.php?acs"
		}
	},
	oneloginRedirectSP: {
		entityID: "http://sp.example.com/demo1/metadata.php",
		credentials: [
			credentialFixtures.sp1
		],
		endpoints: {
			assert: {
				redirect: "http://sp.example.com/demo1/index.php?acs"
			}
		}
	},
	oneloginIDP: {
		entityID: "http://idp.example.com/metadata.php",
		credentials: [
			credentialFixtures.idp1
		],
		endpoints: {
			login: "http://idp.example.com/demo1/index.php?acs"
		}
	},
	oneloginRedirectIDP: {
		entityID: "http://idp.example.com/metadata.php",
		credentials: [
			credentialFixtures.idp1
		],
		endpoints: {
			login: {
				redirect: "http://idp.example.com/demo1/index.php?acs"
			}
		}
	}
};
