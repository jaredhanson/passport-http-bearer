/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , AuthenticationError = require('./errors/authenticationerror');

function Strategy(options, validate) {
  if (typeof options == 'function') {
    validate = options;
    options = {};
  }
  if (!validate) throw new Error('HTTP Bearer authentication strategy requires a validate function');
  
  passport.Strategy.call(this);
  this.name = 'bearer';
  this._validate = validate;
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
  else if (req.body && req.body['access_token']) {
    token = req.body['access_token'];
  }
  else if (req.query && req.query['access_token']) {
    token = req.query['access_token'];
  }
  
  if (!token) { return this.fail(this._challenge()); }
  
  var self = this;
  this._validate(token, function(err, user) {
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
