const jwt = require('jwt-simple');
const User = require('../models/user');
const secrets =  require('../secrets.js');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, secrets.secretString) // sub "subject" and iat "issued at time" and JWT web standards
}

exports.signin = function(req, res, next) {
  // User has already had their email and password auth'd
  // We just need to give them a token
  res.send( { token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;
  // validate user provided data
  if(!email || !password) {
    return res.status(422).send({ error:  'you must provide an email and password'});
  }
  // See if a user with a given email exists
  User.findOne( {email: email }, function(err, existingUser) {
    if (err) { return next(err); }
    // If a user with email does exist, return an error
    if(existingUser) {
      return res.status(422).send({ error: 'email is in use' }); // 422 - "unprocessable entity"
    }
    // if a user with that email does NOT exist create and save a new user record 
    const user  = new User({
      email: email,
      password: password,
    });
    user.save(function(err) {
      if(err) { return next(err); };
      // respons to request indicating that the user was created
      res.json({ token: tokenForUser(user) });
    });
  });

}