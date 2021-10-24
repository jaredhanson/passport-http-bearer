var chai = require('chai');
var Strategy = require('../lib/strategy');


describe('Strategy', function() {
  
  var strategy = new Strategy(function(token, cb) {
    throw new Error('verify function should not be called');
  });
  
  
  it('should be named bearer', function() {
    expect(strategy.name).to.equal('bearer');
  });
  
  it('should challenge request without credentials', function(done) {
    chai.passport.use(strategy)
      .fail(function(challenge, status) {
        expect(challenge).to.equal('Bearer realm="Users"');
        expect(status).to.be.undefined;
        done();
      })
      .authenticate();
  });
  
  it('should challenge request with non-bearer scheme', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==';
      })
      .fail(function(challenge, status) {
        expect(challenge).to.equal('Bearer realm="Users"');
        expect(status).to.be.undefined;
        done();
      })
      .authenticate();
  });
  
  it('should challenge request with scheme name differing by suffix', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'Bearer2 mF_9.B5f-4.1JqM';
      })
      .fail(function(challenge, status) {
        expect(challenge).to.equal('Bearer realm="Users"');
        expect(status).to.be.undefined;
        done();
      })
      .authenticate();
  });
  
  it('should challenge request with scheme name differing by prefix', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'XBearer mF_9.B5f-4.1JqM';
      })
      .fail(function(challenge, status) {
        expect(challenge).to.equal('Bearer realm="Users"');
        expect(status).to.be.undefined;
        done();
      })
      .authenticate();
  });
  
  it('should refuse request with token transmitted in more than one method', function(done) {
    chai.passport.use(strategy)
      .fail(function(status) {
        expect(status).to.equal(400);
        done();
      })
      .request(function(req) {
        req.headers['authorization'] = 'Bearer mF_9.B5f-4.1JqM';
        req.query = {};
        req.query.access_token = 'mF_9.B5f-4.1JqM';
      })
      .authenticate();
  });
  
  it('should refuse request with malformed authorization header', function(done) {
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'Bearer';
      })
      .fail(function(status) {
        expect(status).to.equal(400);
        done();
      })
      .authenticate();
  });
  
  describe('with realm option', function() {
    
    it('should challenge request with realm', function(done) {
      var strategy = new Strategy({ realm: 'example' }, function(token, cb) {
        throw new Error('verify function should not be called');
      });
      
      chai.passport.use(strategy)
        .fail(function(challenge, status) {
          expect(challenge).to.equal('Bearer realm="example"');
          expect(status).to.be.undefined;
          done();
        })
        .authenticate();
    });
    
  }); // with realm option
  
  describe('with scope option', function() {
    
    it('should challenge request with scope as array', function(done) {
      var strategy = new Strategy({ scope: ['profile', 'email']  }, function(token, cb) {
        throw new Error('verify function should not be called');
      });
      
      chai.passport.use(strategy)
        .fail(function(challenge, status) {
          expect(challenge).to.equal('Bearer realm="Users", scope="profile email"');
          expect(status).to.be.undefined;
          done();
        })
        .authenticate();
    });
    
    it('should challenge request with scope as string', function(done) {
      var strategy = new Strategy({ scope: 'profile' }, function(token, cb) {
        throw new Error('verify function should not be called');
      });
      
      chai.passport.use(strategy)
        .fail(function(challenge, status) {
          expect(challenge).to.equal('Bearer realm="Users", scope="profile"');
          expect(status).to.be.undefined;
          done();
        })
        .authenticate();
    });
    
  }); // with scope option
  
  it('should throw if constructed without a verify callback', function() {
    expect(function() {
      new Strategy();
    }).to.throw(TypeError, 'HTTPBearerStrategy requires a verify callback');
  });
  
});
