var chai = require('chai')
  , passportStrategy = require('chai-passport-strategy');

chai.use(passportStrategy);


global.expect = chai.expect;
