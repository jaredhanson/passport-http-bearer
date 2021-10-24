var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('Strategy', function() {
    
  var strategy = new Strategy(function(token, done) {
    if (token == 'vF9dft4qmT') { 
      return done(null, { id: '1234' }, { scope: 'read' });
    }
    return done(null, false);
  });
  
  describe('valid token', function() {
    
    var strategy = new Strategy(function(token, cb) {
      expect(token).to.equal('mF_9.B5f-4.1JqM');
      return cb(null, { id: '248289761001' }, { scope: [ 'profile', 'email' ] });
    });
  
  
    it('should authenticate request with token in header field', function(done) {
      chai.passport.use(strategy)
        .request(function(req) {
          req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        })
        .success(function(user, info) {
          expect(user).to.deep.equal({ id: '248289761001' });
          expect(info).to.deep.equal({ scope: [ 'profile', 'email' ] });
          done();
        })
        .authenticate();
    }); // should authenticate request with token in header field
  
    it('should authenticate request with token in form-encoded body parameter', function(done) {
      chai.passport.use(strategy)
        .success(function(user, info) {
          expect(user).to.deep.equal({ id: '248289761001' });
          expect(info).to.deep.equal({ scope: [ 'profile', 'email' ] });
          done();
        })
        .request(function(req) {
          req.body = {};
          req.body.access_token = 'mF_9.B5f-4.1JqM';
        })
        .authenticate();
    });
    
    it('should authenticate request with token in URI query parameter', function(done) {
      chai.passport.use(strategy)
        .success(function(user, info) {
          expect(user).to.deep.equal({ id: '248289761001' });
          expect(info).to.deep.equal({ scope: [ 'profile', 'email' ] });
          done();
        })
        .request(function(req) {
          req.query = {};
          req.query.access_token = 'mF_9.B5f-4.1JqM';
        })
        .authenticate();
    }); // should authenticate request with token in URI query parameter
  
  }); // valid token
  
  describe('invalid token', function() {
    
    var strategy = new Strategy(function(token, cb) {
      return cb(null, false);
    });
    
    
    it('should refuse request', function(done) {
      chai.passport.use(strategy)
        .fail(function(challenge, status) {
          expect(challenge).to.equal('Bearer realm="Users", error="invalid_token"');
          expect(status).to.be.undefined;
          done();
        })
        .request(function(req) {
          req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        })
        .authenticate();
    }); // should refuse request
    
  }); // invalid token
  
  
  
  
  
  
  describe('handling a request without credentials', function() {
    var challenge;
    
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(c) {
          challenge = c;
          done();
        })
        .request(function(req) {
        })
        .authenticate();
    });
    
    it('should fail with challenge', function() {
      expect(challenge).to.be.a.string;
      expect(challenge).to.equal('Bearer realm="Users"');
    });
  });
  
});
