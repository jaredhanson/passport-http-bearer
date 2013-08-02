var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('strategy failing with description as string', function() {
    
  var strategy = new Strategy(function(token, done) {
    if (token == 'vF9dft4qmT') { 
      return done(null, { id: '1234' }, { scope: 'read' });
    }
    return done(null, false, 'The access token expired');
  });
  
  describe('handling a request with invalid credential in header', function() {
    var challenge;
    
    before(function(done) {
      chai.passport(strategy)
        .fail(function(c) {
          challenge = c;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'Bearer NOT-vF9dft4qmT';
        })
        .authenticate();
    });
    
    it('should fail with challenge', function() {
      expect(challenge).to.be.a.string;
      expect(challenge).to.equal('Bearer realm="Users", error="invalid_token", error_description="The access token expired"');
    });
  });
  
});

describe('strategy failing with description as message key', function() {
    
  var strategy = new Strategy(function(token, done) {
    if (token == 'vF9dft4qmT') { 
      return done(null, { id: '1234' }, { scope: 'read' });
    }
    return done(null, false, { message: 'The access token expired' });
  });
  
  describe('handling a request with invalid credential in header', function() {
    var challenge;
    
    before(function(done) {
      chai.passport(strategy)
        .fail(function(c) {
          challenge = c;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'Bearer NOT-vF9dft4qmT';
        })
        .authenticate();
    });
    
    it('should fail with challenge', function() {
      expect(challenge).to.be.a.string;
      expect(challenge).to.equal('Bearer realm="Users", error="invalid_token", error_description="The access token expired"');
    });
  });
  
});
