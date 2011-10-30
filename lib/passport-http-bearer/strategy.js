/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util');

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
Strategy.prototype._challenge = function() {
  var challenge = 'Bearer realm="' + this._realm + '"';
  if (this._scope) {
    challenge += ', scope="' + this._scope.join(' ') + '"';
  }
  
  return challenge;
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
