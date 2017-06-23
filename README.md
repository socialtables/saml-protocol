# SAML-Protocol
[![CircleCI](https://circleci.com/gh/socialtables/saml-protocol.svg?style=svg&circle-token=505111c7c23aa347b341f48992c91bff9199a5cc)](https://circleci.com/gh/socialtables/saml-protocol)

A framework-agnostic SAML protocol implementation intended to support both
ends of SSO handshakes.

## Features:

- request construction and response ingestion for service providers
- request ingestion and response construction for identity providers
- metadata creation and ingestion for both IDPs and SPs
- request and response signing and verification
- response encryption and decryption
- response validation
- HTTP POST and Redirect protocol bindings

## Compatibility

Node 4+; Makes use of numerous ES6 features.

## Usage example - making an AuthnRequest as a service provider

```
    const saml = require("saml-protocol");

    const spConfig = {
        entityID: "https://your.domain.name.com",
        credentials: [
            {
                certificate: "your X509 signing certificate in PEM format",
                privateKey: "your certificate's private key in PEM format"
            }
        ],
        endpoints: {
            assert: "https://your.domain.name.com/your/consumer/endpoint"
        }
    };
    const idpConfig = {
        entityID: "https://your.idps.domain.name.com",
        credentials: [
            {
                certificate: "your IDPs signing certificate in PEM format"
            }
        ],
        endpoints: {
            login: "https://your.idps.domain.name.com/their/login/endpoint"
        }
    };

    const model = < your model instance >;  # we'll come back to this later

    const sp = new saml.ServiceProvider(spConfig, model);
    const requestDescriptor = sp.produceAuthnRequest(idpConfig);
    ...
```

## API

### Configuration Objects

The library uses configuration objects to define identity and service providers.
These objects are similar, and have the following fields:

- `entityID` **[required]**: the entity ID of the SP or IDP
- `credentials`: a list of credentials in X509 format. When multiple credentials are present, the entities making requests will use the first, and entities consuming them will use them as a resolution chain (allowing for use of certificate rotation).
  - `certificate` **[required]**: an X509 certificate in PEM format
  - `privateKey`: the corresponding private key - required for signing and decryption
  - `use`: either "signing" or "encryption". leave out for credentials that can be used for both.
- `endpoints` **[required]**: a map of endpoints describing the way your service consumes requests/responses
  - `login` **[required for IDPs]**: the SSO login endpoint URL. Can be a string or an object with keys `redirect` and `post` to allow use of separate redirect and post binding endpoints or restriction to either mechanism.
  - `assert` **[required for SPs]**: the SSO assertion consumer endpoint URL. Can be a string or an object with keys `redirect` and `post` to allow use of separate redirect and post binding endpoints or restriction to either mechanism.
- `nameIDFormats`: optional list of NameID formats that this entity supports.
- `signAllRequests`: optional - set to true to force signing for outgoing authentication requests.
- `signAllResponses`: optional - set to true to force signing for outgoing assertions.
- `requireSignedRequests`: optional - set to true to require incoming authentication requests to be signed.
- `requireSignedResponses`: optional - set to true to require incoming assertions to be signed.

### Model Instances

In order to persist and retrieve data, a `model` parameter is required for both
IDPs and SPs. The model must implement the following functions, all of which must
return promises:

#### For Service Providers

- `getIdentityProvider(entityID)`: resolves an IDP's config object by Entity ID
- `storeRequestID(requestID, idpConfig)`: stores a request ID for later verification
- `verifyRequestID(requestID, idpConfig)`: verifies that a request with requestID was sent by the SP, rejecting on failure
- `invalidateRequestID(requestID, idpConfig)`: invalidates a request ID after a response has been processed to prevent duplicate assertion playback attacks

#### For Identity Providers

- `getServiceProvider(entityID)`: resolves an SP's config object by Entity ID

### ServiceProvider Methods

- `produceAuthnRequest(idpConfig)`: resolves to an object describing a request to the IDP, with either a post or redirect binding which is automatically selected based on the IDP's configuration. Contains the following properties:
  - `method`: either "POST" or "GET", indicating what flavor of HTTP request the user's browser should make to the IDP. The library automatically selects a post or redirect binding based on the IDP's configuration.
  - `url`: a URL object indicating the URL to which the user should be sent, including query parameters for redirect bindings
  - `contentType`: the content type to use when a post request is produced
  - `formBody`: the form parameters to send in a post request to the IDP

- `consumePostResponse(formParams)`: accepts form parameters sent to an assertion post endpoint, and resolves to a description of the assertion or rejects with an error. In the event of success, will resolve the following properties:
  - `idp`: the config for the IDP which sent the assertion
  - `nameID`: the NameID sent in the assertion
  - `nameIDFormat`: the format of the NameID
  - `attributes`: an array of attributes describing the user, with the following properties:
    - `name`: the attribute name
    - `friendlyName`: a human-readable version of the attribute name if it exists
    - `values`: an array of values

- `consumeRedirectResponse(queryParams)`: accepts query parameters sent to an assertion redirect endpoint, and resolves to a description of the assertion or rejects with an error. In the event of success, will resolve the following properties:
  - `idp`: the config for the IDP which sent the assertion
  - `nameID`: the NameID sent in the assertion
  - `nameIDFormat`: the format of the NameID
  - `attributes`: an array of attributes describing the user, with the following properties:
    - `name`: the attribute name
    - `friendlyName`: a human-readable version of the attribute name if it exists
    - `values`: an array of values

- `produceSPMetadata()`: returns a string containing the SP's XML metadata, the standard for passing configuration between SAML-supporting entities

- `getIDPFromMetadata(xml)`: accepts an IDP's XML metadata and produces a config object for use with this library

### IdentityProvider Methods

- `consumePostRequest(formParams)`: accepts form parameters sent to a login post endpoint, and resolves to a description of the request or rejects with an error. In the event of success, will resolve the following properties:
  - `idp`: the config for the recipient IDP
  - `sp`: the config for the requesting SP
  - `requestID`: the ID of the authentication request
  - `nameID`: an object containing `format` and `allowCreate` attributes if the SP sent them.

- `consumeRedirectRequest(queryParams)`: accepts query parameters sent to a login redirect endpoint, and resolves to a description of the request or rejects with an error. In the event of success, will resolve the following properties:
  - `idp`: the config for the recipient IDP
  - `sp`: the config for the requesting SP
  - `requestID`: the ID of the authentication request
  - `nameID`: an object containing `format` and `allowCreate` attributes if the SP sent them.

- `produceSuccessResponse(spConfig, inResponseTo, nameID, attributes)`: builds an assertion to send to the service provider after login. accepts a service provider configuration, a request ID to which this assertion is responding, the nameID of the user, and the attributes of the user. Resolves an object describing where to send the user with the following properties:
  - `method`: either "POST" or "GET", indicating what flavor of HTTP request the user's browser should make to the IDP. The library automatically selects a post or redirect binding based on the SP's configuration.
  - `url`: a URL object indicating the URL to which the user should be sent, including query parameters for redirect bindings
  - `contentType`: the content type to use when a post request is produced
  - `formBody`: the form parameters to send in a post request to the SP

- `produceFailureResponse(spConfig, inResponseTo, errorMessage)`: builds an error response to send to the service provider after login. accepts a service provider configuration, a request ID to which this message is responding, and an error message. Resolves an object describing where to send the user with the following properties:
  - `method`: either "POST" or "GET", indicating what flavor of HTTP request the user's browser should make to the IDP. The library automatically selects a post or redirect binding based on the SP's configuration.
  - `url`: a URL object indicating the URL to which the user should be sent, including query parameters for redirect bindings
  - `contentType`: the content type to use when a post request is produced
  - `formBody`: the form parameters to send in a post request to the SP

- `produceIDPMetadata()`: returns a string containing the IDP's XML metadata, the standard for passing configuration between SAML-supporting entities

- `getSPFromMetadata(xml)`: accepts an SP's XML metadata and produces a config object for use with this library
