const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Simple in-memory user store (for demo purposes, use a real database in production)
let users = [];

// Register a new user
function register(username, password) {
  // Hash password before saving
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  // Store the user
  users.push({ username, password: hashedPassword });

  return { username };
}

// Login a user and return a JWT token
function login(username, password) {
  const user = users.find(u => u.username === username);
  if (!user) {
    throw new Error('User not found');
  }

  const isMatch = bcrypt.compareSync(password, user.password);
  if (!isMatch) {
    throw new Error('Incorrect password');
  }

  // Generate JWT token
  const token = jwt.sign({ username }, 'your_jwt_secret_key', { expiresIn: '1h' });
  return { token };
}

// Middleware to authenticate JWT token
function authenticate(socket, next) {
  const token = socket.handshake.query.token;

  if (!token) {
    return next(new Error('Authentication required'));
  }

  try {
    const decoded = jwt.verify(token, 'your_jwt_secret_key');
    socket.username = decoded.username;
    next();
  } catch (err) {
    next(new Error('Authentication failed'));
  }
}

module.exports = { register, login, authenticate };
