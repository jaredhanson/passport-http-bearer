var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('Strategy', function() {
    
  var strategy = new Strategy(function(token, done) {
    if (token == 'vF9dft4qmT') { 
      return done(null, { id: '1234' }, { scope: 'read' });
    }
    return done(null, false);
  });
  
  describe('handling a request with capitalized scheme', function() {
    var user
      , info;
    
    before(function(done) {
      chai.passport(strategy)
        .success(function(u, i) {
          user = u;
          info = i;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'BEARER vF9dft4qmT';
        })
        .authenticate();
    });
    
    it('should supply user', function() {
      expect(user).to.be.an.object;
      expect(user.id).to.equal('1234');
    });
    
    it('should supply info', function() {
      expect(info).to.be.an.object;
      expect(info.scope).to.equal('read');
    });
  });
  
  describe('handling a request with scheme at beginning of input', function() {
    var challenge;
    
    before(function(done) {
      chai.passport(strategy)
        .fail(function(c) {
          challenge = c;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'BearerX vF9dft4qmT';
        })
        .authenticate();
    });
    
    it('should fail with challenge', function() {
      expect(challenge).to.be.a.string;
      expect(challenge).to.equal('Bearer realm="Users"');
    });
  });
  
  describe('handling a request with scheme at end of input', function() {
    var challenge;
    
    before(function(done) {
      chai.passport(strategy)
        .fail(function(c) {
          challenge = c;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'XBearer vF9dft4qmT';
        })
        .authenticate();
    });
    
    it('should fail with challenge', function() {
      expect(challenge).to.be.a.string;
      expect(challenge).to.equal('Bearer realm="Users"');
    });
  });
  
  describe('handling a request with non-Bearer credentials', function() {
    var challenge;
    
    before(function(done) {
      chai.passport(strategy)
        .fail(function(c) {
          challenge = c;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'XXXXX vF9dft4qmT';
        })
        .authenticate();
    });
    
    it('should fail with challenge', function() {
      expect(challenge).to.be.a.string;
      expect(challenge).to.equal('Bearer realm="Users"');
    });
  });
  
});
