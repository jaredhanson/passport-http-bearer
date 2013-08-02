var chai = require('chai')
  , passport = require('chai-passport-strategy');

chai.use(passport);


window.expect = chai.expect;
