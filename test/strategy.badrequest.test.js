var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('strategy handling bad requests', function() {
    
  var strategy = new Strategy(function(token, done) {
    if (token == 'vF9dft4qmT') { 
      return done(null, { id: '1234' }, { scope: 'read' });
    }
    return done(null, false);
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
  
  describe('handling a request with malformed Authorization header', function() {
    var status;
    
    before(function(done) {
      chai.passport(strategy)
        .fail(function(s) {
          status = s;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'Bearer';
        })
        .authenticate();
    });
    
    it('should fail with status', function() {
      expect(status).to.be.a.number;
      expect(status).to.equal(400);
    });
  });
  
  describe('handling a request with credentials included in multiple ways', function() {
    var status;
    
    before(function(done) {
      chai.passport(strategy)
        .fail(function(s) {
          status = s;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'BEARER vF9dft4qmT';
          req.query = {};
          req.query.access_token = "vF9dft4qmT";
        })
        .authenticate();
    });
    
    it('should fail with status', function() {
      expect(status).to.be.a.number;
      expect(status).to.equal(400);
    });
  });
  
});
