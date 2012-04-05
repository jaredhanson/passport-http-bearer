/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , AuthenticationError = require('./errors/authenticationerror');


/**
 * `Strategy` constructor.
 *
 * The HTTP Bearer authentication strategy authenticates requests based on
 * a bearer token contained in the `Authorization` header field, `access_token`
 * body parameter, or `access_token` query parameter.
 *
 * Applications must supply a `verify` callback which accepts a `token`, and
 * then calls the `done` callback supplying a `user`, which should be set to
 * `false` if the token is not valid.  If a token-related authentication error
 * occurs, `err` should be set to an `AuthenticationError` containing relevant
 * information to be returned to the client in the authentication challenge.  If
 * an exception occured, `err` should be set to a generic `Error`.
 *
 * Options:
 *   - `realm`  authentication realm, defaults to "Users"
 *   - `scope`  list of scope values indicating the required scope of the access token for accessing the requested resource
 *
 * Examples:
 *
 *     passport.use(new BearerStrategy(
 *       function(token, done) {
 *         User.findByToken({ token: token }, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           if (!sufficientScope(user, token)) { return done(new bearer.AuthenticationError('', 'insufficient_scope')); }
 *           return done(null, user);
 *         });
 *       }
 *     ));
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('HTTP Bearer authentication strategy requires a verify function');
  
  passport.Strategy.call(this);
  this.name = 'bearer';
  this._verify = verify;
  this._realm = options.realm || 'Users';
  if (options.scope) {
    this._scope = (Array.isArray(options.scope)) ? options.scope : [ options.scope ];
  }
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Bearer authorization
 * header, body parameter, or query parameter.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  var token = undefined;
  
  if (req.headers && req.headers['authorization']) {
    var parts = req.headers['authorization'].split(' ');
    if (parts.length == 2) {
      var scheme = parts[0]
        , credentials = parts[1];
        
      if (/Bearer/i.test(scheme)) {
        token = credentials;
      }
    } else {
      return this.fail(400);
    }
  }

  if (req.body && req.body['access_token']) {
    if(token) return this.fail(400);
    token = req.body['access_token'];
  }

  if (req.query && req.query['access_token']) {
    if(token) return this.fail(400);
    token = req.query['access_token'];
  }
  
  if (!token) { return this.fail(this._challenge()); }
  
  var self = this;
  this._verify(token, function(err, user) {
    if (err instanceof AuthenticationError) {
      var status;
      if (err.code === 'invalid_request') { status = 400; }
      else if (err.code === 'insufficient_scope') { status = 403; }
      
      return self.fail(self._challenge(err.code, err.message, err.uri), status);
    }
    if (err) { return self.error(err); }
    if (!user) { return self.fail(self._challenge()); }
    self.success(user);
  });
}

/**
 * Authentication challenge.
 *
 * @api private
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
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
