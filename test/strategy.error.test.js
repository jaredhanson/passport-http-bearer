var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('Strategy', function() {
  
  describe('that encounters an error during verification', function() {
    var strategy = new Strategy(function(token, done) {
      return done(new Error('something went wrong'));
    });
  
    describe('handling a request', function() {
      var err;
    
      before(function(done) {
        chai.passport(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer vF9dft4qmT';
          })
          .authenticate();
      });
    
      it('should error', function() {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('something went wrong');
      });
    });
  });
  
});
