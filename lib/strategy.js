// Module dependencies.
var passport = require('passport-strategy')
  , util = require('util');


/**
 * Create a new `Strategy` object.
 *
 * @classdesc This `Strategy` authenticates requests that use the Bearer
 * authentication scheme.  Alternatively, the access token can be included in
 * an `access_token` body or query parameter.  The credential is a bearer
 * token, and any party in possession of the token can use it to get access
 *
 * The HTTP Bearer authentication strategy authenticates requests based on
 * a bearer token contained in the `Authorization` header field, `access_token`
 * body parameter, or `access_token` query parameter.
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
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
  
  /** The name of the strategy, which is set to `'bearer'`.
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
 * The access token will be parsed from either the HTTP "Authorization" header,
 * an `access_token` body parameter, or an `access_token` query parameter.  If
 * an access token is present, the verify function will be called to
 * authenticate the request.
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
 *          passed through for additional request processing.
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
 *          passed through for additional request processing.
 */
