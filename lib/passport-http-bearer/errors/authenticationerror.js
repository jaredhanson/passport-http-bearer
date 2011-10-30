/**
 * `AuthenticationError` error.
 *
 * @api public
 */
function AuthenticationError(message, code, uri) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'AuthenticationError';
  this.message = message || null;
  this.code = code || 'invalid_token';
  this.uri = uri;
};

/**
 * Inherit from `Error`.
 */
AuthenticationError.prototype.__proto__ = Error.prototype;


/**
 * Expose `AuthenticationError`.
 */
module.exports = AuthenticationError;
