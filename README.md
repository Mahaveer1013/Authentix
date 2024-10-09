# Authentix

**Authentix** is an authentication package that simplifies user authentication by providing easy-to-use functions for user signup, login, token generation, middleware, and Google OAuth authentication.

## Features

- Easy configuration of user database
- Support for username/password or email/password authentication
- Google OAuth authentication
- Token-based authentication with access and refresh tokens
- Middleware for token verification
- Simple API for user authentication

## Installation

```bash
npm install authentix
```

## user-model.js

```
import { configureDB } from 'authentix';

const userSchema = new Schema({
  email: { type: String, required: false},
  username: { type: String, required: false},
  password: { type: String, required: false },
});

const User = mongoose.model('User', userSchema);

//Configure Your Database, username and password is the mongodb field key
configureDB(User, {primaryField: 'username', passwordField: 'password', google: 'email'})
```

## routes.js

```
import { setConfig, emailSignup, googleLogin, login, loginRequired, logout, signup, verifyOtp } from 'authentix';

const config_data = {
  JWT_SECRET_KEY:  'your-secret-key-goes-here',
  GOOGLE_CLIENT_ID: 'your-google-client-id-goes-here'
}

setConfig(config_data) // the provided secret keys would be used for further processes

// ===========> Login routes <===============
app.post('/auth/google', googleLogin); //
app.post('/credential-login', login);
app.post('/credential-signup', signup);
app.post('/email-login', emailSignup);
app.post('/verify-otp', verifyOtp);
app.post('/email-signup', signup);
app.get('/logout', logout);
```


## <h1>Authentix</h1>

Authentix is an authentication package that simplifies user authentication by providing easy-to-use functions for user signup, login, token generation, middleware, and Google OAuth authentication.


## <h1>Features</h1>

=> Easy configuration of user database
=> Support for username/password or email/password authentication
=> Google OAuth authentication
=> Token-based authentication with access and refresh tokens
=> Middleware for token verification
=> Simple API for user authentication


## <h1>Installation</h1>
```
npm install authentix
```


## <h1>Configuration</h1>

To get started, you need to configure your user database and set up the authentication fields.


## <h1>User Model Configuration</h1>

First, define your user schema and configure the database with authentix.

```
// user-model.js
import mongoose from 'mongoose';
import { configureDB } from 'authentix';

const userSchema = new mongoose.Schema({
  email: { type: String, required: false },
  username: { type: String, required: false },
  password: { type: String, required: false },
});

const User = mongoose.model('User', userSchema);

// Configure your database, primary field, and password field
configureDB(User, {
  primaryField: 'username', // or 'email'
  passwordField: 'password',
  google: 'email' // field used for Google OAuth
});
```


## <h1>Setting Up Routes</h1>

Set up your authentication routes using authentix functions.

```
// routes.js
import express from 'express';
import { setConfig, emailSignup, googleLogin, login, loginRequired, logout, signup, verifyOtp } from 'authentix';

const app = express();

const config_data = {
  JWT_SECRET_KEY: 'your-secret-key-goes-here',
  GOOGLE_CLIENT_ID: 'your-google-client-id-goes-here'
};

// Set the configuration for authentix
setConfig(config_data);

// Define your authentication routes
app.post('/auth/google', googleLogin);          // Google OAuth login
app.post('/credential-login', login);           // Credential login
app.post('/credential-signup', signup);         // Credential signup
app.post('/email-login', emailSignup);          // Email login
app.post('/verify-otp', verifyOtp);             // Verify OTP
app.post('/email-signup', signup);              // Email signup
app.get('/logout', logout);                     // Logout

// Example of a protected route
app.get('/protected', loginRequired, (req, res) => {
  res.send('This is a protected route');
});

// Start the server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

## <h1>Rules</h1>

=> Make sure to use the loginRequired middleware from authentix, as we have stored the access and refresh tokens in the cookies with httpOnly:true, so that those cookies cant be accessible from frontend (To make it secure from XSS attacks).
