const express = require("express");
const passport = require("passport");
const bodyParser = require("body-parser");
const connectEnsureLogin = require("connect-ensure-login"); // Ensures user still has a valid login session
const session = require("express-session");
const User = require("./models/userModel");

const app = express(); // express app

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());

// Configure the app to use sessions
// Session is a way to store data on the server between requests.
// Since we didn't specify which server store to use, the default MemoryStore is being used.
// so that we can access it on subsequent requests
// in this case, we are storing the authenticated user id for the duration of the session
app.use(
  session({
    name: "bj:sessionId", // by default is "connect.sid", but should be changed if you have multiple apps running on the same domian (localhost)
    secret: process.env.SESSION_SECRET, // used to sign the session ID cookie
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 }, // 1 hour
  })
);

app.use(passport.initialize()); // initialize passport middleware
app.use(passport.session()); // use passport session middleware cause our app uses persistent login sessions
require("./middlewares/passport"); // making app aware of the passport middlewares

app.get("/", async (req, res, next) => {
  console.log(req.user);
  return res.status(200).send("Welcome to our app!");
});

app.get(
  "/profile",
  connectEnsureLogin.ensureLoggedIn("/login"),
  async (req, res, next) => {
    console.log(req.user);
    return res
      .status(200)
      .send(`Welcome to your profile ${req.user.username}!`);
  }
);

app.post("/signup", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return next(new Error("Provide username and password."));
    }
    const user = await User.create({ username, password });
    passport.authenticate(
      "local",
      {
        failureRedirect: "/login",
        failureMessage: "Try logging again!",
      },
      (err, user, info) => {
        if (err) return next(err);
        if (!user) {
          return next(new Error(info.message));
        }
        req.logIn(user, (err) => {
          if (err) return next(err);
          res.redirect(302, "/profile");
        });
      }
    )(req, res, next);
  } catch (error) {
    return next(error);
  }
});

app.get("/login", passport.authenticate("facebook"));
app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/profile");
  }
);
app.post("/login", (req, res, next) => {
  passport.authenticate(
    "local",
    {
      failureRedirect: "/login",
      failureMessage: "Try logging again!",
    },
    (err, user, info) => {
      if (err) return next(err);
      if (!user) {
        return next(new Error(info.message));
      }
      req.logIn(user, { session: true }, (err) => {
        if (err) return next(err);
        res.redirect(302, "/profile");
      });
    }
  )(req, res, next);
});

app.get("/logout", (req, res, next) => {
  req.logOut({ keepSessionInfo: false }, (err) => {
    if (err) return next(err);
  });
  res.redirect("/");
});

// app.use((err, req, res, next) => {
//   const statusCode = err.statusCode || 500;
//   const message = err.message || "Internal server error!";
//   return res.status(statusCode).json({ success: false, message });
// });

module.exports = app;
