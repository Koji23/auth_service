const passport = require('passport');
const User = require('../models/user');
const secrets = require('../secrets.js');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create Local Strategy
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy( localOptions, function(email, password, done) {
  // Verify this username and password, call done with the user
  // if it is the correct username and password, otherwise call done with false
  User.findOne({ email: email }, function(err, user){
    if(err) { return done(err); }
    if(!user) { return done(null, false); }

    // Compare Passwords - is 'password' equal to user.password?
    user.comparePassword(password, function(err, isMatch) {
      if(err) { return done(err); }
      if(!isMatch) { return done(null, false); }

      return done(null, user); // done is provided by passport, it will assign 'user' to the req object for use in our routes
    });
  });
});

// Setup options for JWT strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: secrets.secretString,
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // See if the user Id in the payload exists in our database
  // if it does, call 'done' wtih that user
  // otherwise, call done without a user object
  User.findById(payload.sub, function(err, user) {
    if(err) { return done(err, false); }

    if(user) {
      done(null, user);
    } else {
      done(null, false); // there was no error, but there was no user
    }
  });
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);