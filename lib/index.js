/**
 * HTTP Bearer authentication.
 *
 * The `passport-http-bearer` module provides a {@link https://www.passportjs.org/ Passport}
 * strategy for authenticating an HTTP request using the Bearer authentication
 * scheme.
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
