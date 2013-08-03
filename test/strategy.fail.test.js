var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('Strategy', function() {
    
  describe('failing a request with message string', function() {
    var strategy = new Strategy(function(token, done) {
      if (token == 'vF9dft4qmT') { 
        return done(null, { id: '1234' }, { scope: 'read' });
      }
      return done(null, false, 'The access token expired');
    });
  
    describe('handling a request with wrong token', function() {
      var challenge;
    
      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer WRONG';
          })
          .authenticate();
      });
    
      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users", error="invalid_token", error_description="The access token expired"');
      });
    });
  });
  
  describe('failing a request with hash containing message', function() {
    var strategy = new Strategy(function(token, done) {
      if (token == 'vF9dft4qmT') { 
        return done(null, { id: '1234' }, { scope: 'read' });
      }
      return done(null, false, { message: 'The access token expired' });
    });
  
    describe('handling a request with wrong token', function() {
      var challenge;
    
      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer WRONG';
          })
          .authenticate();
      });
    
      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users", error="invalid_token", error_description="The access token expired"');
      });
    });
  });
  
});
