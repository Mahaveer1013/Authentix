const { configureDB } = require('./lib/db');
const { signup, login, loginRequired, googleLogin, loginLimiter, logout } = require('./lib/auth');
const { setConfig } = require('./lib/config');
const { emailSignup, verifyOtp } = require('./lib/gmailAuth');

module.exports = {
  configureDB,
  signup,
  login,
  loginRequired,
  setConfig,
  googleLogin, 
  loginLimiter,
  logout,
  emailSignup,
  verifyOtp
};
