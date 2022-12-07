# passport-http-bearer

HTTP Bearer authentication strategy for [Passport](https://www.passportjs.org/).

This module lets you authenticate HTTP requests using [bearer tokens](https://www.passportjs.org/concepts/bearer-token/),
as specified by [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750), in your
Node.js applications.  By plugging into Passport, bearer token support can be
easily and unobtrusively integrated into any application or framework that
supports [Connect](https://github.com/senchalabs/connect#readme)-style
middleware, including [Express](https://expressjs.com/).

<div align="center">

:hammer_and_wrench: [API Reference](https://www.passportjs.org/api/passport-http-bearer/1.x/?utm_source=github&utm_medium=referral&utm_campaign=passport-http-bearer&utm_content=nav-api) •
:heart: [Sponsors](https://www.passportjs.org/sponsors/?utm_source=github&utm_medium=referral&utm_campaign=passport-http-bearer&utm_content=nav-sponsors)

</div>

---

<p align="center">
  <sup>Advertisement</sup>
  <br>
  <a href="https://click.linksynergy.com/link?id=D*o7yui4/NM&offerid=507388.1672410&type=2&murl=https%3A%2F%2Fwww.udemy.com%2Fcourse%2Fnodejs-express-mongodb-bootcamp%2F&u1=1Mxk3SNFcRAr3r8tfxCmy64nCmTFQ1TmsTeVpqTwkquLPYaKN">Node.js, Express, MongoDB & More: The Complete Bootcamp 2020</a><br>Master Node by building a real-world RESTful API and web app (with authentication, Node.js security, payments & more)
</p>

---

[![npm](https://img.shields.io/npm/v/passport-http-bearer.svg)](https://www.npmjs.com/package/passport-http-bearer)
[![build](https://img.shields.io/travis/jaredhanson/passport-http-bearer.svg)](https://travis-ci.org/jaredhanson/passport-http-bearer)
[![coverage](https://img.shields.io/coveralls/jaredhanson/passport-http-bearer.svg)](https://coveralls.io/github/jaredhanson/passport-http-bearer)
[...](https://github.com/jaredhanson/passport-http-bearer/wiki/Status)

## Install

    $ npm install passport-http-bearer

#### TypeScript support

```bash
$ npm install @types/passport-http-bearer
```

## Usage

#### Configure Strategy

The HTTP Bearer authentication strategy authenticates users using a bearer
token.  The strategy requires a `verify` callback, which accepts that
credential and calls `done` providing a user.  Optional `info` can be passed,
typically including associated scope, which will be set by Passport at
`req.authInfo` to be used by later middleware for authorization and access
control.

```js
passport.use(new BearerStrategy(
  function(token, done) {
    User.findOne({ token: token }, function (err, user) {
      if (err) { return done(err); }
      if (!user) { return done(null, false); }
      return done(null, user, { scope: 'all' });
    });
  }
));
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'bearer'` strategy, to
authenticate requests.  Requests containing bearer tokens do not require session
support, so the `session` option can be set to `false`.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```js
app.get('/profile', 
  passport.authenticate('bearer', { session: false }),
  function(req, res) {
    res.json(req.user);
  });
```

#### Issuing Tokens

Bearer tokens are typically issued using OAuth 2.0.  [OAuth2orize](https://github.com/jaredhanson/oauth2orize)
is a toolkit for implementing OAuth 2.0 servers and issuing bearer tokens.  Once
issued, this module can be used to authenticate tokens as described above.

#### Making authenticated requests
The HTTP Bearer authentication strategy authenticates requests based on a bearer token contained in the:
* `Authorization` header field where the value is in the format `{scheme} {token}` and scheme is "Bearer" in this case.
* or `access_token` body parameter
* or `access_token` query parameter

## Examples

For a complete, working example, refer to the [Bearer example](https://github.com/passport/express-4.x-http-bearer-example).

## Related Modules

- [OAuth2orize](https://github.com/jaredhanson/oauth2orize) — OAuth 2.0 authorization server toolkit

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2011-2013 Jared Hanson <[https://www.jaredhanson.me/](https://www.jaredhanson.me/)>
