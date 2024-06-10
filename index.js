import dotenv from 'dotenv';
dotenv.config({ path: 'mail.env' });

import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

// Debug: Log environment variables
console.log("GMAIL_USER:", process.env.GMAIL_USER); // Debug: Check if environment variables are loaded
console.log("DATABASE_URL:", process.env.DATABASE_URL); // Debug: Check if database URL is loaded

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not set");
  process.exit(1);
}

const app = express();
const port = 3000;

const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
});

db.connect()
  .then(() => console.log('Connected to the database'))
  .catch(err => {
    console.error('Database connection error:', err.stack);
    process.exit(1); // Exit the application if database connection fails
  });

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs'); // Set EJS as the template engine

// Routes
app.get('/', (req, res) => res.render('home'));
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));
app.get('/forgotpassword', (req, res) => res.render('forgotpassword'));
app.get('/reset/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const result = await db.query('SELECT * FROM users WHERE reset_password_token = $1 AND reset_password_expires > NOW()', [token]);
    if (result.rows.length > 0) {
      res.render('reset', { token });
    } else {
      res.send('Password reset token is invalid or has expired.');
    }
  } catch (err) {
    console.error('Error fetching reset token:', err);
    res.status(500).send('Server error');
  }
});
app.get('/chat', (req, res) => res.render('chat'));

// Register route
app.post('/register', async (req, res) => {
  const { username: email, password } = req.body;
  try {
    const checkResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (checkResult.rows.length > 0) {
      res.send('Email already exists. Try logging in.');
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashedPassword]);
      res.render('secrets');
    }
  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).send('Server error');
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { username: email, password } = req.body;
  try {
    const checkResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (checkResult.rows.length > 0) {
      const user = checkResult.rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        res.redirect('/chat');
      } else {
        res.send('Incorrect Information');
      }
    } else {
      res.send('User not found');
    }
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).send('Server error');
  }
});

// Forgot password route
app.post('/forgotpassword', async (req, res) => {
  const { username: email } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const token = crypto.randomBytes(20).toString('hex');
      const expires = new Date(Date.now() + 3600000); // 1 hour

      await db.query('UPDATE users SET reset_password_token = $1, reset_password_expires = $2 WHERE email = $3', [token, expires, email]);

      const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: process.env.GMAIL_USER
          ,
          pass: process.env.GMAIL_PASS,
        },
      });

      const mailOptions = {
        to: user.email,
        from: 'passwordreset@demo.com',
        subject: 'Password Reset',
        text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
        Please click on the following link, or paste this into your browser to complete the process:\n\n
        http://${req.headers.host}/reset/${token}\n\n
        If you did not request this, please ignore this email and your password will remain unchanged.\n`,
      };

      await transporter.sendMail(mailOptions);

      res.send(`An e-mail has been sent to ${user.email} with further instructions.`);
    } else {
      res.send('No account with that email address exists.');
    }
  } catch (err) {
    console.error('Error during forgot password:', err);
    res.status(500).send('Server error');
  }
});

// Reset password route
app.post('/reset/:token', async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.send('Passwords do not match.');
  }

  try {
    const result = await db.query('SELECT * FROM users WHERE reset_password_token = $1 AND reset_password_expires > NOW()', [token]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.query('UPDATE users SET password = $1, reset_password_token = NULL, reset_password_expires = NULL WHERE email = $2', [hashedPassword, user.email]);
      res.send('Your password has been updated.');
    } else {
      res.send('Password reset token is invalid or has expired.');
    }
  } catch (err) {
    console.error('Error during reset password:', err);
    res.status(500).send('Server error');
  }
});

// Start the server
app.listen(port, () => console.log(`Server running on port ${port}`));
