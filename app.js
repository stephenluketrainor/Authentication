//jshint esversion:6
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const mongoose = require("mongoose");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const app = express();

app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(
  session({
    secret: "keyboard cats are the best",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGODBURI, { useNewUrlParser: true });

const db = mongoose.connection;
db.on("error", (err) => {
  console.log(err);
});
db.once("open", () => {
  console.log("Successfully connected to mongoose database");
});

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true }, // values: email address, googleId, facebookId
  password: String,
  provider: String, // values: 'local', 'google', 'facebook'
  email: String,
  secret: String, // Suggest you move this to a collection of its own
});

userSchema.plugin(passportLocalMongoose, {
  usernameField: "username",
});
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user.id);
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "https://secrets-app-h80j.onrender.com/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate(
        { username: profile.id },
        {
          provider: "google",
          email: profile._json.email,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", (req, res) => {
  res.render("login");
});

// this is the new login route, which authenticates first and THEN
// does the login (which is required to create the session)
// A failed login (wrong password) will give the browser error
// "unauthorized".
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/secrets", nocache, function (req, res) {
  // The below line was added so we can't display the "/secrets" page
  // after we logged out using the "back" button of the browser, which
  // would normally display the browser cache and thus expose the
  // "/secrets" page we want to protect.

  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.post("/secrets", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  User.register(
    {
      username: req.body.username,
      email: req.body.username,
      provider: "local",
    },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.listen(process.env.PORT || 3000, () => {
  console.log("listening on port 3000");
});

function nocache(req, res, next) {
  res.header("Cache-Control", "private, no-cache, no-store, must-revalidate");
  res.header("Expires", "-1");
  res.header("Pragma", "no-cache");
  next();
}
