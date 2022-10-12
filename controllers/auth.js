const bcrypt = require('bcryptjs');
const User = require('../models/user');

exports.getLogin = (req, res, next) => {
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    isAuthenticated: false,
  });
};

exports.getSignup = (req, res, next) => {
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false,
  });
};

exports.postLogin = (req, res, next) => {
  const { email, password } = req.body;

  User.findOne({ email })
    .then((user) => {
      if (!user) {
        return res.redirect('/login');
      }

      // validate password
      bcrypt
        .compare(password, user.password)
        .then((isMatched) => {
          if (isMatched) {
            // save session info
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save((err) => {
              console.log(err);
              res.redirect('/');
            });
          }
          res.redirect('/login');
        })
        .catch((err) => {
          console.log(err);
          res.redirect('/login');
        });
    })
    .catch((err) => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const { email, password, confirmPassword } = req.body;

  // add validation here

  User.findOne({ email })
    .then((user) => {
      // if user email already exist, redirect to signup page
      if (user) return res.redirect('/signup');

      // encrypt password
      return bcrypt
        .hash(password, 12)
        .then((encryptedPassword) => {
          // create new user
          const user = new User({
            email,
            password: encryptedPassword,
            cart: { items: [] },
          });

          return user.save();
        })
        .then((result) => res.redirect('/login'));
    })
    .catch((err) => console.log(err));
};

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.log(err);
    res.redirect('/');
  });
};
