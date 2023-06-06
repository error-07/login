const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
const port = 3000;

const { ExpressOIDC } = require('@okta/oidc-middleware');
const OktaJwtVerifier = require('@okta/jwt-verifier');


// Create a PostgreSQL connection pool
const pool = new Pool({
  user: 'basith',
  host: 'localhost',
  database: 'login',
  password: '123',
  port: 5432,
});

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Okta configuration

const oktaClientId = '0oa5nqcnj0PQldVws697';
const oktaClientSecret = 'O-xTzGtqx0hP8Vc4LIgAAUnbmVsphRLqSsnc0uo-';
const oktaDomain = 'https://trial-6218819.okta.com';
const oktaRedirectUri = 'http://localhost:3000/okta/callback'; // Update with your desired redirect URI

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: 'https://trial-6218819.okta.com/oauth2/default', // Replace with your Okta domain
  clientId: oktaClientId, // Replace with your Okta client ID
});

function validateIdToken(idToken) {
  return oktaJwtVerifier.verifyAccessToken(idToken, 'api://default');
}


// Register route - GET
app.get('/register', (req, res) => {
  res.send(`
    <h1>Register</h1>
    <form method="POST" action="/register">
      <label>Name:</label>
      <input type="text" name="name" required><br>
      <label>Email:</label>
      <input type="email" name="email" required><br>
      <label>Password:</label>
      <input type="password" name="password" required><br>
      <label>Confirm Password:</label>
      <input type="password" name="confirmPassword" required><br>
      <label>Is Admin:</label>
      <input type="checkbox" name="is_admin"><br>
      <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="/login">Login</a></p>
  `);
});

// Register route - POST
app.post('/register', async (req, res) => {
  try {
    const { name, email, password, confirmPassword, is_admin } = req.body;

    // Check if the user already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (existingUser.rowCount > 0) {
      return res.status(409).send(`
        <script>
          alert('User already exists');
          window.location.href = '/register';
        </script>
      `);
    }

    // Check if the passwords match
    if (password !== confirmPassword) {
      return res.status(400).send(`
        <script>
          alert('Passwords do not match');
          window.location.href = '/register';
        </script>
      `);
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the user into the database
    await pool.query(
      'INSERT INTO users (name, email, password, is_admin) VALUES ($1, $2, $3, $4)',
      [name, email, hashedPassword, is_admin]
    );

    // Redirect to Okta login
    const authorizeUrl = `https://trial-6218819.okta.com/oauth2/v1/authorize?client_id=okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26&code_challenge=cDr4-y5GTwdgL7oQuNQtM29rXh4JDt27OiLaI__SFpU&code_challenge_method=S256&nonce=32NvikMRyATMXhfRc0zgP1YAko4qUP77C0WX4Arr8ew240CSOn3IS9YDFfaxrGnV&redirect_uri=https%3A%2F%2Ftrial-6218819.okta.com%2Fenduser%2Fcallback&response_type=code&state=X9dcItSlyRWTHYn3qKqN1wzbd3ea0w1vj7RI9z46uFrZadFTL9zjfPl5JTFyukIf&scope=openid%20profile%20email%20okta.users.read.self%20okta.users.manage.self%20okta.internal.enduser.read%20okta.internal.enduser.manage%20okta.enduser.dashboard.read%20okta.enduser.dashboard.manage`;
    res.redirect(authorizeUrl);
   
    if (window.location.href.includes('https://trial-6218819.okta.com/app/UserHome?session_hint=AUTHENTICATED')) {
      // Redirect to the desired URL
      window.location.href = 'http://localhost:3000/welcome';
    }
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).send(`
      <script>
        alert('An error occurred during registration');
        window.location.href = '/register';
      </script>
    `);
  }
  res.send(`
    <h1>Registration Successful</h1>
    <p>Your account has been created successfully.</p>
    <a href="/login">Login</a>
  `);
});

// Okta callback route
app.get('/okta/callback', (req, res) => {
  res.redirect('/welcome');
});

// Welcome route
app.get('/welcome', async (req, res) => {
  try {
    const idToken = req.query.token; // Assuming the token is passed as a query parameter
    
    // Validate the ID token using Okta
    const jwt = await validateIdToken(idToken);
    const username = jwt.claims.sub; // Assuming the username is stored in the 'sub' claim of the JWT
   
    const oktaJwtVerifier = new OktaJwtVerifier({
      issuer: `${process.env.OKTA_ORG_URL}/oauth2/default`,
      clientId: process.env.OKTA_CLIENT_ID,
    });
    
    async function validateIdToken(idToken) {
      try {
        const jwt = await oktaJwtVerifier.verifyAccessToken(idToken, 'api://default');
        return jwt;
      } catch (error) {
        throw new Error('Invalid ID token');
      }
    }
    res.send(`
      <h1>Welcome</h1>
      <p>You are now logged in as ${username}.</p>
      <a href="/logout">Logout</a>
    `);
  } catch (error) {
    console.error('Error during token validation:', error);
    res.status(500).send(`
      <script>
        alert('An error occurred during token validation');
        window.location.href = '/login';
      </script>
    `);
  }
});


// Login route - GET
app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form method="POST" action="/login">
      <label>Email:</label>
      <input type="email" name="email" required><br>
      <label>Password:</label>
      <input type="password" name="password" required><br>
      <button type="submit">Login</button>
    </form>
    <p>Don't have an account? <a href="/register">Register</a></p>
  `);
});

// Login route - POST
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Retrieve the user from the database
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    // Check if the user exists
    if (!user) {
      return res.status(404).send(`
        <script>
          alert('User not found');
          window.location.href = '/login';
        </script>
      `);
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).send(`
        <script>
          alert('Invalid password');
          window.location.href = '/login';
        </script>
      `);
    }

    // Redirect to Okta login
    const authorizeUrl = `https://trial-6218819.okta.com/oauth2/v1/authorize?client_id=okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26&code_challenge=cDr4-y5GTwdgL7oQuNQtM29rXh4JDt27OiLaI__SFpU&code_challenge_method=S256&nonce=32NvikMRyATMXhfRc0zgP1YAko4qUP77C0WX4Arr8ew240CSOn3IS9YDFfaxrGnV&redirect_uri=https%3A%2F%2Ftrial-6218819.okta.com%2Fenduser%2Fcallback&response_type=code&state=X9dcItSlyRWTHYn3qKqN1wzbd3ea0w1vj7RI9z46uFrZadFTL9zjfPl5JTFyukIf&scope=openid%20profile%20email%20okta.users.read.self%20okta.users.manage.self%20okta.internal.enduser.read%20okta.internal.enduser.manage%20okta.enduser.dashboard.read%20okta.enduser.dashboard.manage`;
    res.redirect(authorizeUrl);
   if (window.location.href.includes('https://trial-6218819.okta.com/app/UserHome?session_hint=AUTHENTICATED')) {
    // Redirect to the desired URL
    window.location.href = 'http://localhost:3000/welcome';
  }
    } catch (error) {
    console.error('Error during login:', error);
    res.status(500).send(`
      <script>
        alert('An error occurred during login');
        window.location.href = '/login';
      </script>
    `);
  }
});

// Logout route


app.get('/logout', (req, res) => {
  res.send(`
    <h1>Logout</h1>
    <p>You have been logged out successfully.</p>
    <a href="/login">Login again</a>
  `);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


