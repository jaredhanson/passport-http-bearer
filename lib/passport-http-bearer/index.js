/**
 * Module dependencies.
 */
var Strategy = require('./strategy')
  , AuthenticationError = require('./errors/authenticationerror');


/**
 * Framework version.
 */
exports.version = '0.1.0';

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;

exports.AuthenticationError = AuthenticationError;
