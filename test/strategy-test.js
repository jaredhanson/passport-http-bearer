var vows = require('vows');
var assert = require('assert');
var util = require('util');
var bearer = require('passport-http-bearer');
var BearerStrategy = require('passport-http-bearer/strategy');


vows.describe('BearerStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new BearerStrategy(function() {});
    },
    
    'should be named bearer': function (strategy) {
      assert.equal(strategy.name, 'bearer');
    },
  },
  
  'strategy handling a valid request with authorization header': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.headers = {};
        req.headers.authorization = 'Bearer vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
    },
  },
  
  'strategy handling a valid request with form-encoded body': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.body = {};
        req.body.access_token = 'vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
    },
  },
  
  'strategy handling a valid request with URI query': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.query = {};
        req.query.access_token = 'vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
    },
  },
  
  'strategy handling a request that is not validated': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(null, false);
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.headers = {};
        req.headers.authorization = 'Bearer vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Bearer realm="Users"');
      },
    },
  },
  
  'strategy handling a request that encounters an error during verification': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(new Error('something went wrong'));
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
        }
        
        req.headers = {};
        req.headers.authorization = 'Bearer vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
      },
    },
  },
  
  'strategy handling a request that encounters an AuthenticationError during validation': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(new bearer.AuthenticationError());
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        }
        
        req.headers = {};
        req.headers.authorization = 'Bearer vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.isUndefined(status);
        assert.equal(challenge, 'Bearer realm="Users", error="invalid_token"');
      },
    },
  },
  
  'strategy handling a request that encounters an AuthenticationError with message during validation': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(new bearer.AuthenticationError('The access token expired'));
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        }
        
        req.headers = {};
        req.headers.authorization = 'Bearer vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.isUndefined(status);
        assert.equal(challenge, 'Bearer realm="Users", error="invalid_token", error_description="The access token expired"');
      },
    },
  },
  
  'strategy handling a request that encounters an AuthenticationError with message and code during validation': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(new bearer.AuthenticationError('The access token lacks email scope', 'insufficient_scope'));
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        }
        
        req.headers = {};
        req.headers.authorization = 'Bearer vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 403);
        assert.equal(challenge, 'Bearer realm="Users", error="insufficient_scope", error_description="The access token lacks email scope"');
      },
    },
  },
  
  'strategy handling a request that encounters an AuthenticationError with message, code, and uri during validation': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(new bearer.AuthenticationError('The access token lacks email scope', 'insufficient_scope', 'http://www.example.com/errors/12345'));
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        }
        
        req.headers = {};
        req.headers.authorization = 'Bearer vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 403);
        assert.equal(challenge, 'Bearer realm="Users", error="insufficient_scope", error_description="The access token lacks email scope", error_uri="http://www.example.com/errors/12345"');
      },
    },
  },
  
  'strategy handling a request that encounters an AuthenticationError with code set to invalid_request': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(new bearer.AuthenticationError('', 'invalid_request'));
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge, status) {
          self.callback(null, challenge, status);
        }
        
        req.headers = {};
        req.headers.authorization = 'Bearer vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 400);
        assert.equal(challenge, 'Bearer realm="Users", error="invalid_request"');
      },
    },
  },
  
  'strategy handling a request without authorization credentials': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Bearer realm="Users"');
      },
    },
  },
  
  'strategy handling a request with non-Bearer authorization header': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.headers = {};
        req.headers.authorization = 'XXXXX vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Bearer realm="Users"');
      },
    },
  },
  
  'strategy handling a request with malformed authorization header': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }
        
        req.headers = {};
        req.headers.authorization = 'Bearer';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with 400 Bad Request' : function(err, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 400);
      },
    },
  },
  
  'strategy handling a valid request with BEARER scheme in capitalized letters': {
    topic: function() {
      var strategy = new BearerStrategy(function(token, done) {
        done(null, { token: token });
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.headers = {};
        req.headers.authorization = 'BEARER vF9dft4qmT';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.token, 'vF9dft4qmT');
      },
    },
  },
  
  'strategy handling a request without authorization credentials and realm option set': {
    topic: function() {
      var strategy = new BearerStrategy({ realm: 'Administrators' },
        function(token, done) {
          done(null, { token: token });
        });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Bearer realm="Administrators"');
      },
    },
  },
  
  'strategy handling a request without authorization credentials and scope option set': {
    topic: function() {
      var strategy = new BearerStrategy({ scope: 'email' },
        function(token, done) {
          done(null, { token: token });
        });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Bearer realm="Users", scope="email"');
      },
    },
  },
  
  'strategy handling a request without authorization credentials and multiple scope options set': {
    topic: function() {
      var strategy = new BearerStrategy({ scope: ['email', 'feed'] },
        function(token, done) {
          done(null, { token: token });
        });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Bearer realm="Users", scope="email feed"');
      },
    },
  },
  
  'strategy constructed without a validate callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new BearerStrategy() });
    },
  },
  
}).export(module);
