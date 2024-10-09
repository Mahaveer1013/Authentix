let User;
let primaryField = 'username';
let passwordField = 'password';
let google = 'email';

const configureDB = (userModel, options = {}) => {
  User = userModel;
  primaryField = options.primaryField;
  google = options.google;
  passwordField = options.passwordField;
};

const getUserModel = () => {
  console.log(User, '\n\n\n\n\n');
  if (!User) {
    throw new Error('User model is not configured. Please configure the database.');
  }
  return User;
};

console.log(getUserModel());


const getUsernameField = () => primaryField;
const getPasswordField = () => passwordField;
const getEmailField = () => google;

module.exports = { configureDB, getUserModel, getUsernameField, getEmailField, getPasswordField };
