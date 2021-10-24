var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('Strategy', function() {
    
  var strategy = new Strategy(function(token, done) {
    if (token == 'vF9dft4qmT') { 
      return done(null, { id: '1234' }, { scope: 'read' });
    }
    return done(null, false);
  });
  
  it('should authenticate request with token in header', function(done) {
    var strategy = new Strategy(function(token, cb) {
      expect(token).to.equal('mF_9.B5f-4.1JqM');
      return cb(null, { id: '248289761001' }, { scope: [ 'profile', 'email' ] });
    });
    
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
  });
  
  describe('handling a request with valid token in form-encoded body parameter', function() {
    var user
      , info;
    
    before(function(done) {
      chai.passport.use(strategy)
        .success(function(u, i) {
          user = u;
          info = i;
          done();
        })
        .request(function(req) {
          req.body = {};
          req.body.access_token = 'vF9dft4qmT';
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
  
  describe('handling a request with valid credential in URI query parameter', function() {
    var user
      , info;
    
    before(function(done) {
      chai.passport.use(strategy)
        .success(function(u, i) {
          user = u;
          info = i;
          done();
        })
        .request(function(req) {
          req.query = {};
          req.query.access_token = 'vF9dft4qmT';
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
  
  describe('handling a request with wrong token in header', function() {
    var challenge;
    
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(c) {
          challenge = c;
          done();
        })
        .request(function(req) {
          req.headers.authorization = 'Bearer WRONG';
        })
        .authenticate();
    });
    
    it('should fail with challenge', function() {
      expect(challenge).to.be.a.string;
      expect(challenge).to.equal('Bearer realm="Users", error="invalid_token"');
    });
  });
  
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
