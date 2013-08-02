var Strategy = require('../lib/strategy');


describe('Strategy', function() {
    
  var strategy = new Strategy(function(){});
    
  it('should be named bearer', function() {
    expect(strategy.name).to.equal('bearer');
  });
  
  it('constructed without a verify callback', function() {
    expect(function() {
      new Strategy();
    }).to.throw(TypeError, 'passport-http-bearer.Strategy requires a verify callback');
  });
  
});