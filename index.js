require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const connectDB = require('./MongoConnector');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { hashPassword, comparePassword, schemas } = require('./Schema');
const path = require('path');

const app = express();
connectDB();

const User = require('./models/User');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));


app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  store: MongoStore.create({
    client: mongoose.connection.getClient(),
    crypto: {
      secret: process.env.MONGODB_SESSION_SECRET
    }
  }),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 3600000,
    httpOnly: true
  }
}));

function requireAdmin(req, res, next) {

  const user = req.session.user;

  if (!user) {
    return res.redirect('/login');
  }

  if (user.type !== 'admin') {
    return res.status(403).render('404', {
      title: "403 Forbidden",
      name: user.name,
      message: "You are not authorized to view the admin page."
    });
  }

  next();
}


app.get('/', (req, res) => {
  res.render('index', { title: "Home", name: req.session.user?.name || null });
});

app.get('/signup', (req, res) => {
  res.render('signup', { title: "Sign Up", error: null });
});

app.post('/signupSubmit', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const { error } = schemas.signup.validate({ name, email, password });
    if (error) {
      return res.render('signup', { title: "Sign Up", error: error.details[0].message });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ name, email, password: hashedPassword, user_type: 'user' });
    await newUser.save();

    req.session.user = {
      id: newUser._id,
      name: newUser.name,
      email: newUser.email,
      type: newUser.user_type
    };
    res.redirect('/members');
  } catch (err) {
    res.render('signup', { title: "Sign Up", error: "Signup failed: " + err.message });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { title: "Login", error: null, preservedEmail: '' });
});

app.post('/loginSubmit', async (req, res) => {
  const { email, password } = req.body;
  const { error } = schemas.login.validate({ email, password });

  if (error) {
    return res.render('login', {
      title: "Login",
      error: error.details[0].message,
      preservedEmail: email
    });
  }

  try {
    const user = await User.findOne({ email: new RegExp(`^${email}$`, 'i') });

    if (!user) {
      return res.render('login', { title: "Login", error: "Email not found", preservedEmail: email });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.render('login', { title: "Login", error: "Incorrect password", preservedEmail: email });
    }

    req.session.user = {
      name: user.name,
      email: user.email,
      type: user.user_type
    };

    res.redirect('/members');
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { title: "Login", error: "Something went wrong", preservedEmail: email });
  }

});


app.get('/members', (req, res) => {
  if (!req.session.user) return res.redirect('/');

  const images = ['image1.jpg', 'image2.jpg', 'image3.jpg'];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.render('members', {
    title: "Members",
    name: req.session.user.name,
    image: randomImage
  });
});

app.get('/admin', requireAdmin, async (req, res) => {
  const users = await User.find().lean();
  res.render('admin', {
    title: "Admin Panel",
    name: req.session.user.name,
    users
  });
});

app.get('/promote/:email', requireAdmin, async (req, res) => {
  await User.updateOne({ email: req.params.email }, { $set: { user_type: 'admin' } });
  res.redirect('/admin');
});

app.get('/demote/:email', requireAdmin, async (req, res) => {
  await User.updateOne({ email: req.params.email }, { $set: { user_type: 'user' } });
  res.redirect('/admin');
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error('Logout error:', err);
    res.redirect('/');
  });
});

app.use((req, res) => {
  res.status(404).render('404', { title: "Not Found" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
