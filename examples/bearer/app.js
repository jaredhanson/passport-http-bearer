var express = require('express')
  , passport = require('passport')
  , util = require('util')
  , BearerStrategy = require('passport-http-bearer').Strategy;


var users = [
    { id: 1, username: 'bob', token: '123456789', email: 'bob@example.com' }
  , { id: 2, username: 'joe', token: 'abcdefghi', email: 'joe@example.com' }
];

function findByToken(token, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    if (user.token === token) {
      return fn(null, user);
    }
  }
  return fn(null, null);
}


// Use the BearerStrategy within Passport.
//   Strategies in Passport require a `validate` function, which accept
//   credentials (in this case, a token), and invoke a callback with a user
//   object.
passport.use(new BearerStrategy({
  },
  function(token, done) {
    // asynchronous validation, for effect...
    process.nextTick(function () {
      
      // Find the user by token.  If there is no user with the given token, set
      // the user to `false` to indicate failure.  Otherwise, return the
      // authenticated `user`.  Note that in a production-ready application, one
      // would want to validate the token for authenticity.
      findByToken(token, function(err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false); }
        return done(null, user);
      })
    });
  }
));

/* 
// Return back the request object example by passing in options "passReqToCallback": true
// Use the BearerStrategy within Passport.
//   Strategies in Passport require a `validate` function, which accept
//   credentials (in this case, a token), and invoke a callback with a user
//   object.
passport.use(new BearerStrategy({ "passReqToCallback": true },
  function(req, token, done) {
  	
  	//req is passed back here
  	console.log(req);
    // asynchronous validation, for effect...
    process.nextTick(function () {
      
      // Find the user by token.  If there is no user with the given token, set
      // the user to `false` to indicate failure.  Otherwise, return the
      // authenticated `user`.  Note that in a production-ready application, one
      // would want to validate the token for authenticity.
      findByToken(token, function(err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false); }
        return done(null, user);
      })
    });
  }
));
*/



var app = express.createServer();

// configure Express
app.configure(function() {
  app.use(express.logger());
  // Initialize Passport!  Note: no need to use session middleware when each
  // request carries authentication credentials, as is the case with HTTP
  // Bearer.
  app.use(passport.initialize());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});


// curl -v http://127.0.0.1:3000/?access_token=123456789
app.get('/',
  // Authenticate using HTTP Bearer credentials, with session support disabled.
  passport.authenticate('bearer', { session: false }),
  function(req, res){
    res.json({ username: req.user.username, email: req.user.email });
  });

app.listen(3000);
