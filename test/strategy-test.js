var vows = require('vows');
var assert = require('assert');
var util = require('util');
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
  
  'strategy constructed without a validate callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new BearerStrategy() });
    },
  },
  
}).export(module);
