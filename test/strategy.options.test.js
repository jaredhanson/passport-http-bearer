var chai = require('chai')
  , Strategy = require('../lib/strategy');


describe('Strategy', function() {

  describe('with realm option', function() {
    var strategy = new Strategy({ realm: 'Administrators' }, function(token, done) {
      if (token == 'vF9dft4qmT') {
        return done(null, { id: '1234' }, { scope: 'read' });
      }
      return done(null, false);
    });

    describe('handling a request without credentials', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Administrators"');
      });
    });
  });

  describe('strategy with scope option', function() {
    var strategy = new Strategy({ scope: 'email' }, function(token, done) {
      if (token == 'vF9dft4qmT') {
        return done(null, { id: '1234' }, { scope: 'read' });
      }
      return done(null, false);
    });

    describe('handling a request without credentials', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users", scope="email"');
      });
    });
  });

  describe('strategy with scope option set to array', function() {
    var strategy = new Strategy({ scope: ['email', 'feed'] }, function(token, done) {
      if (token == 'vF9dft4qmT') {
        return done(null, { id: '1234' }, { scope: 'read' });
      }
      return done(null, false);
    });

    describe('handling a request without credentials', function() {
      var challenge;

      before(function(done) {
        chai.passport(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="Users", scope="email feed"');
      });
    });
  });

  describe('strategy with allow no token option', function() {
    var strategy = new Strategy({ allowNoToken: true }, function(token, done) {
      if (token == 'vF9dft4qmT') {
        return done(null, { id: '1234' });
      }
      return done(null, {});
    });

    describe('handling a request with token in header', function() {
      var user;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u) {
            user = u;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer vF9dft4qmT';
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });
    });

    describe('handling a request without token', function() {
      var user;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u) {
            user = u;
            done();
          })
          .authenticate();
      });

      it('should supply empty user', function() {
        expect(user).to.be.an.object;
        expect(user).to.be.empty();
      });
    });
  });
});
