// Module dependencies.
var passport = require('passport-strategy')
  , util = require('util');


/**
 * Create a new `Strategy` object.
 *
 * @classdesc This `Strategy` authenticates HTTP requests that use the Bearer
 * authentication scheme, as specified by {@link https://www.rfc-editor.org/rfc/rfc6750 RFC 6750}.
 *
 * The bearer token credential can be sent in the HTTP request in one of three
 * different ways.  Preferably, the token is sent in the "Authorization" header
 * field:
 *
 * ```http
 * GET /resource HTTP/1.1
 * Host: server.example.com
 * Authorization: Bearer mF_9.B5f-4.1JqM
 * ```
 *
 * Alternatively, the token can be sent in a form-encoded body, using the
 * `access_token` parameter:
 *
 * ```http
 * POST /resource HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * access_token=mF_9.B5f-4.1JqM
 * ```
 *
 * Or, in the URL, using the `access_token` query parameter:
 *
 * ```http
 * GET /resource?access_token=mF_9.B5f-4.1JqM HTTP/1.1
 * Host: server.example.com
 * ```
 *
 * @public
 * @class
 * @augments base.Strategy
 * @param {Object} [options]
 * @param {string} [options.realm='Users'] - Value indicating the protection
 *          space over which credentials are valid.
 * @param {string} [options.scope] - Value indicating required scope needed to
 *          access protected resources.
 * @param {boolean} [options.passReqToCallback=false] - When `true`, the
 *          `verify` function receives the request object as the first argument,
 *          in accordance with the `{@link Strategy~verifyWithReqFn}` signature.
 * @param {Strategy~verifyFn|Strategy~verifyWithReqFn} verify - Function which
 *          verifies access token.
 *
 * @example
 * var BearerStrategy = require('passport-http-bearer').Strategy;
 *
 * new BearerStrategy(function(token, cb) {
 *   tokens.findOne({ value: token }, function(err, claims) {
 *     if (err) { return cb(err); }
 *     if (!claims) { return cb(null, false); }
 *
 *     users.findOne({ id: claims.userID }, function (err, user) {
 *       if (err) { return cb(err); }
 *       if (!user) { return cb(null, false); }
 *       return cb(null, user, { scope: claims.scope });
 *     });
 *   });
 * });
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('HTTPBearerStrategy requires a verify function'); }
  
  passport.Strategy.call(this);
  
  /** The name of the strategy, set to `'bearer'`.
   *
   * @type {string}
   * @readonly
   */
  this.name = 'bearer';
  this._verify = verify;
  this._realm = options.realm || 'Users';
  if (options.scope) {
    this._scope = (Array.isArray(options.scope)) ? options.scope : [ options.scope ];
  }
  this._passReqToCallback = options.passReqToCallback;
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request by verifying access token.
 *
 * When a bearer token is sent in the request, it will be parsed and the verify
 * function will be called to verify the token and authenticate the request.  If
 * a token is not present, authentication will fail with the appropriate
 * challenge and status code.
 *
 * This function is protected, and should not be called directly.  Instead,
 * use `passport.authenticate()` middleware and specify the {@link Strategy#name `name`}
 * of this strategy and any options.
 *
 * @protected
 * @param {http.IncomingMessage} req - The Node.js {@link https://nodejs.org/api/http.html#class-httpincomingmessage `IncomingMessage`}
 *          object.
 *
 * @example
 * passport.authenticate('bearer');
 */
Strategy.prototype.authenticate = function(req) {
  var token;
  
  if (req.headers && req.headers.authorization) {
    var parts = req.headers.authorization.split(' ');
    if (parts.length == 2) {
      var scheme = parts[0]
        , credentials = parts[1];
        
      if (/^Bearer$/i.test(scheme)) {
        token = credentials;
      }
    } else {
      return this.fail(400);
    }
  }

  if (req.body && req.body.access_token) {
    if (token) { return this.fail(400); }
    token = req.body.access_token;
  }

  if (req.query && req.query.access_token) {
    if (token) { return this.fail(400); }
    token = req.query.access_token;
  }
  
  if (!token) { return this.fail(this._challenge()); }
  
  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) {
      if (typeof info == 'string') {
        info = { message: info }
      }
      info = info || {};
      return self.fail(self._challenge('invalid_token', info.message));
    }
    self.success(user, info);
  }
  
  if (self._passReqToCallback) {
    this._verify(req, token, verified);
  } else {
    this._verify(token, verified);
  }
};

/**
 * Build authentication challenge.
 *
 * @private
 */
Strategy.prototype._challenge = function(code, desc, uri) {
  var challenge = 'Bearer realm="' + this._realm + '"';
  if (this._scope) {
    challenge += ', scope="' + this._scope.join(' ') + '"';
  }
  if (code) {
    challenge += ', error="' + code + '"';
  }
  if (desc && desc.length) {
    challenge += ', error_description="' + desc + '"';
  }
  if (uri && uri.length) {
    challenge += ', error_uri="' + uri + '"';
  }
  
  return challenge;
};

// Export `Strategy`.
module.exports = Strategy;


/**
 * Verifies `token` and yields authenticated user.
 *
 * This function is called by `{@link Strategy}` to verify an access token, and
 * must invoke `cb` to yield the result.
 *
 * @callback Strategy~verifyFn
 * @param {string} token - The access token received in the request.
 * @param {function} cb
 * @param {?Error} cb.err - An `Error` if an error occured; otherwise `null`.
 * @param {Object|boolean} cb.user - An `Object` representing the authenticated
 *          user if verification was successful; otherwise `false`.
 * @param {Object} cb.info - Additional application-specific context that will be
 *          passed through for further request processing.
 */

/**
 * Verifies `token` and yields authenticated user.
 *
 * This function is called by `{@link Strategy}` to verify an access token when
 * the `passReqToCallback` option is set, and must invoke `cb` to yield the
 * result.
 *
 * @callback Strategy~verifyWithReqFn
 * @param {http.IncomingMessage} req - The Node.js {@link https://nodejs.org/api/http.html#class-httpincomingmessage `IncomingMessage`}
 *          object.
 * @param {string} token - The access token received in the request.
 * @param {function} cb
 * @param {?Error} cb.err - An `Error` if an error occured; otherwise `null`.
 * @param {Object|boolean} cb.user - An `Object` representing the authenticated
 *          user if verification was successful; otherwise `false`.
 * @param {Object} cb.info - Additional application-specific context that will be
 *          passed through for further request processing.
 */
