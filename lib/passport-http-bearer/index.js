/**
 * Module dependencies.
 */
var Strategy = require('./strategy')
  , AuthenticationError = require('./errors/authenticationerror');


/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;

exports.AuthenticationError = AuthenticationError;
