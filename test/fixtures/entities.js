import credentialFixtures from './credentials';
import protocol from '../../lib/protocol';

export default {

  // IDPs
  simpleIDP: {
    entityID: 'idp.test.com',
    credentials: [],
    endpoints: {
      login: {
        post: 'https://idp.test.com/saml/login',
        redirect: 'https://idp.test.com/saml/login',
      },
    },
    signAllResponses: false,
    requireSignedRequests: false,
  },
  simpleIDPWithLatency: {
    entityID: 'idp.test.com',
    credentials: [
      credentialFixtures.idp1,
    ],
    endpoints: {
      login: {
        post: 'https://idp.test.com/saml/login',
        redirect: 'https://idp.test.com/saml/login',
      },
    },
    signAllResponses: false,
    requireSignedRequests: false,
    responseLatencyInSecs: 2,
  },
  simpleIDPWithCredentials: {
    entityID: 'idp.test.com',
    credentials: [
      credentialFixtures.idp1,
    ],
    endpoints: {
      login: 'https://idp.test.com/saml/login',
      logout: {
        post: 'https://idp.test.com/saml/logout',
      },
    },
    nameIDFormats: [
      'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    ],
    signAllResponses: true,
    requireSignedRequests: false,
  },

  simpleIDPWithCredentialsAndURIEntityID: {
    entityID: 'https://entityuri-idp.test.com',
    credentials: [
      credentialFixtures.idp1,
    ],
    endpoints: {
      login: 'https://entityuri-idp.test.com/saml/login',
      logout: {
        post: 'https://entityuri-idp.test.com/saml/logout',
      },
    },
    nameIDFormats: [
      'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    ],
    signAllResponses: true,
    requireSignedRequests: false,
  },

  // SPs
  simpleSP: {
    entityID: 'sp.test.com',
    credentials: [],
    endpoints: {
      assert: 'https://sp.test.com/assert',
    },
    forcePassive: false,
    forceAuthentication: false,
    extendedRequirements: {},
    signAllRequests: false,
    requireSignedResponses: false,
    sendAuthnContext: true,
    authnContextClassComparison: 'exact',
    authnContextClasses: [protocol.AUTHNCONTEXT.PASSWORDPROTECTEDTRANSPORT],
  },
  simpleSPWithCredentials: {
    entityID: 'sp.test.com',
    credentials: [
      credentialFixtures.sp1,
      credentialFixtures.sp2,
    ],
    endpoints: {
      assert: 'https://sp.test.com/assert',
    },
    forcePassive: false,
    forceAuthentication: false,
    signAllRequests: true,
    requireSignedResponses: true,
    extendedRequirements: {
      InResponseTo: true,
      NotOnOrAfter: true,
      Recipient: true,
    },
    sendAuthnContext: true,
    authnContextClassComparison: 'exact',
    authnContextClasses: [protocol.AUTHNCONTEXT.PASSWORDPROTECTEDTRANSPORT],
  },
  simpleSPWithCredentialsAndURIEntityID: {
    entityID: 'https://entityuri-idp.test.com',
    credentials: [
      credentialFixtures.sp1,
      credentialFixtures.sp2,
    ],
    endpoints: {
      assert: 'https://entityuri-idp.test.com/assert',
    },
    forcePassive: false,
    forceAuthentication: false,
    signAllRequests: true,
    requireSignedResponses: true,
    extendedRequirements: {
      InResponseTo: true,
      NotOnOrAfter: true,
      Recipient: true,
    },
    sendAuthnContext: true,
    authnContextClassComparison: 'exact',
    authnContextClasses: [protocol.AUTHNCONTEXT.PASSWORDPROTECTEDTRANSPORT],
  },
  oneloginSP: {
    entityID: 'http://sp.example.com/demo1/metadata.php',
    credentials: [
      credentialFixtures.sp1,
    ],
    endpoints: {
      assert: 'http://sp.example.com/demo1/index.php?acs',
    },
    forcePassive: false,
    forceAuthentication: false,
    extendedRequirements: {},
    authnContextClassComparison: 'exact',
    authnContextClasses: [protocol.AUTHNCONTEXT.PASSWORDPROTECTEDTRANSPORT],
  },
  oneloginRedirectSP: {
    entityID: 'http://sp.example.com/demo1/metadata.php',
    credentials: [
      credentialFixtures.sp1,
    ],
    endpoints: {
      assert: {
        redirect: 'http://sp.example.com/demo1/index.php?acs',
      },
    },
    forcePassive: false,
    forceAuthentication: false,
    extendedRequirements: {},
    sendAuthnContext: true,
    authnContextClassComparison: 'exact',
    authnContextClasses: [protocol.AUTHNCONTEXT.PASSWORDPROTECTEDTRANSPORT],
  },
  oneloginIDP: {
    entityID: 'http://idp.example.com/metadata.php',
    credentials: [
      credentialFixtures.idp1,
    ],
    endpoints: {
      login: 'http://idp.example.com/demo1/index.php?acs',
    },
  },
  oneloginRedirectIDP: {
    entityID: 'http://idp.example.com/metadata.php',
    credentials: [
      credentialFixtures.idp1,
    ],
    endpoints: {
      login: {
        redirect: 'http://idp.example.com/demo1/index.php?acs',
      },
    },
  },
};
