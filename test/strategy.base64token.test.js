var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('Strategy', function() {
    
  describe('with base64EncodedToken option enabled', function() {

    var base64DecodedToken = 'vF9dft4qmT'
      , base64EncodedToken = (new Buffer(base64DecodedToken).toString('base64'));

    var strategy = new Strategy({ base64EncodedToken: true }, function(token, done) {
      if (token == base64DecodedToken) { 
        return done(null, { id: '1234' }, { scope: 'read' });
      }
      return done(null, false);
    });
  
    describe('handling a request with valid token', function() {
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
            req.headers.authorization = 'Bearer ' + base64EncodedToken;
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
  });
  
});
