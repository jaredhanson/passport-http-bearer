var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('Strategy', function() {
    
  var strategy = new Strategy(function(token, done) {
    if (token == 'vF9dft4qmT') { 
      return done(null, { id: '1234' }, { scope: 'read' });
    }
    return done(null, false);
  });
  
  describe('handling a request with malformed authorization header', function() {
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
  
  describe('handling a request with token included in more than one way', function() {
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
