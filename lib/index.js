/**
 * The `passport-http-bearer` module provides a {@link https://www.passportjs.org/ Passport}
 * strategy for authenticating {@link https://www.passportjs.org/concepts/bearer-token/ bearer tokens}
 * used in accordance with the HTTP Bearer authentication scheme.
 *
 * Bearer tokens are a credential which can be used by any party in possession
 * of the token to gain access to a protected resource.  Use of a bearer token
 * does not require any additional credentials, such as a cryptographic key.  As
 * such, bearer tokens must be protected from disclosure in both storage and
 * transport in order to be utilized securely.
 *
 * The Bearer authentication scheme is specified by {@link https://www.rfc-editor.org/rfc/rfc6750 RFC 6750}.
 * This scheme was designed for use with access tokens issued using {@link https://www.passportjs.org/concepts/oauth2/ OAuth 2.0}
 * ({@link https://www.rfc-editor.org/rfc/rfc6749 RFC 6749}).  However, this
 * scheme is useable within the general HTTP Authentication framework ({@link https://www.rfc-editor.org/rfc/rfc7235 RFC 7235})
 * and can be utilized to authenticate bearer tokens issued via other mechanisms
 * as well.
 *
 * @module passport-http-bearer
 */


// Module dependencies.
var Strategy = require('./strategy');

/*
 * `{@link Strategy}` constructor.
 *
 * @type {function}
 */
exports = module.exports = Strategy;

/*
 * `{@link Strategy}` constructor.
 *
 * @type {function}
 */
exports.Strategy = Strategy;
