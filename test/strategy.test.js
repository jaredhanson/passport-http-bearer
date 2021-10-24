var chai = require('chai');
var Strategy = require('../lib/strategy');


describe('Strategy', function() {
  
  var strategy = new Strategy(function(token, cb) {
    throw new Error('verify function should not be called');
  });
  
  
  it('should be named bearer', function() {
    expect(strategy.name).to.equal('bearer');
  });
  
  it('should refuse request without credentials', function(done) {
    chai.passport.use(strategy)
      .fail(function(challenge, status) {
        expect(challenge).to.equal('Bearer realm="Users"');
        expect(status).to.be.undefined;
        done();
      })
      .authenticate();
  });
  
  it('should throw if constructed without a verify callback', function() {
    expect(function() {
      new Strategy();
    }).to.throw(TypeError, 'HTTPBearerStrategy requires a verify callback');
  });
  
});
