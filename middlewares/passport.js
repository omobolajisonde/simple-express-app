const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

const User = require("../models/userModel");

// Passport serializes user information to the session on successful authentication of user.
passport.serializeUser(function (user, done) {
  process.nextTick(function () {
    return done(null, {
      id: user.id,
      username: user.username || user.name,
    });
  });
});

// Passport deserializes user information from the session on subsequent requests after successful authentication of user.
passport.deserializeUser(function (user, done) {
  process.nextTick(function () {
    return done(null, user); // updates req.user from being the whole user object to the one specified in the serializeUser function
  });
});

// configuring passport's local strategy
passport.use(
  "local",
  new LocalStrategy(
    {
      usernameField: "username",
      passwordField: "password",
      passReqToCallback: true,
    },
    async (req, username, password, done) => {
      try {
        const user = await User.findOne({ username });
        if (!user || !(await user.isCorrectPassword(password))) {
          return done(null, null, {
            message: "Username or password not correct.",
          });
        }
        return done(null, user); // Serializes user into session and sets req.user = user
      } catch (error) {
        console.log("Here");
        return done(error);
      }
    }
  )
);

// configuring passport's fb strategy
passport.use(
  "facebook",
  new FacebookStrategy(
    {
      clientID: process.env.FB_APP_CLIENT_ID,
      clientSecret: process.env.FB_APP_CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      // console.log(profile);
      done(null, profile._json);
    }
  )
);
