var vows = require('vows');
var assert = require('assert');
var util = require('util');
var bearer = require('passport-http-bearer');


vows.describe('passport-http-bearer').addBatch({
  
  'module': {
    'should report a version': function (x) {
      assert.isString(bearer.version);
    },
  },
  
}).export(module);
