const protocol = {
  NAMEIDFORMAT: {
    EMAILADDRESS: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    UNSPECIFIED: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    PERSISTENT: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    TRANSIENT: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    KERBEROS: 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
    ENTITY: 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
  },
  BINDINGS: {
    REDIRECT: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    POST: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  },
  STATUS: {
    SUCCESS: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    REQUESTER: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
    RESPONDER: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
    VERSIONMISMATCH: 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch',
    AUTHNFAILED: 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
    INVALIDATTRNAMEORVALUE: 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue',
    INVALIDNAMEIDPOLICY: 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy',
    NOAUTHNCONTEXT: 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext',
    NOAVAILABLEIDP: 'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP',
    NOPASSIVE: 'urn:oasis:names:tc:SAML:2.0:status:NoPassive',
    NOSUPPORTEDIDP: 'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP',
    PARTIALLOGOUT: 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
    PROXYCOUNTEXCEEDED: 'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded',
    REQUESTDENIED: 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
    REQUESTUNSUPPORTED: 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported',
    REQUESTVERSIONDEPRECATED: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated',
    REQUESTVERSIONTOOHIGH: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh',
    REQUESTVERSIONTOOLOW: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow',
    RESOURCENOTRECOGNIZED: 'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized',
    TOOMANYRESPONSES: 'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses',
    UNKNOWNATTRPROFILE: 'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile',
    UNKNOWNPRINCIPAL: 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal',
    UNSUPPORTEDBINDING: 'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding',
  },
  AUTHNCONTEXTCOMPARISON: {
    EXACT: 'exact',
    MINIMUM: 'minimum',
    MAXIMUM: 'maximum',
    BETTER: 'better',
  },
  AUTHNCONTEXT: {
    PASSWORD: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
    PASSWORDPROTECTEDTRANSPORT: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    TLSCLIENT: 'urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient',
    X509: 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509',
    WINDOWS: 'urn:federation:authentication:windows',
    KERBEROS: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos',
  },
  CONFIRMATIONMETHODS: {
    HOLDEROFKEY: 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key',
    SENDERVOUCHES: 'urn:oasis:names:tc:SAML:2.0:cm:sender-vouches',
    BEARER: 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
  },
  ATTRNAMEFORMAT: {
    BASIC: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
  },
  default_attribute_mapping: {
    email: [
      'EmailAddress', 'Email', 'email_address', 'mail',
      'urn:oid:1.3.6.1.4.1.5923.1.1.1.6',
    ],
    first_name: [
      'FirstName', 'given_name', 'GivenName',
      'urn:oid:2.5.4.42',
    ],
    last_name: [
      'LastName', 'family_name', 'FamilyName',
      'urn:oid:2.5.4.4',
    ],
  },
};

export default protocol;
