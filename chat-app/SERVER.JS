const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const { register, login, authenticate } = require('./models/auth'); // Import auth functions
const Message = require('./models/message');
const port = process.env.PORT||3000;

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.json());

// Routes for registering and logging in
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  try {
    const newUser = register(username, password);
    res.json(newUser);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  try {
    const token = login(username, password);
    res.json(token);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Set up socket connection with JWT authentication
io.use((socket, next) => {
  authenticate(socket, next); // Check if user is authenticated
});

io.on('connection', (socket) => {
  console.log(`${socket.username} connected`);

  // Listen for chat messages
  socket.on('chat message', (msg) => {
    io.emit('chat message', { username: socket.username, message: msg });
  });

  // Inside 'chat message' event handler
socket.on('chat message', (msg) => {
  const newMessage = new Message({
    username: socket.username,
    message: msg,
  });

  newMessage.save((err) => {
    if (err) console.error('Error saving message:', err);
  });

  io.emit('chat message', { username: socket.username, message: msg });
});

  // Handle user disconnect
  socket.on('disconnect', () => {
    console.log(`${socket.username} disconnected`);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

//Handle private messages
socket.on('private message', (recipient, msg) => {
  const recipientSocket = Object.values(io.sockets.sockets).find(
    (s) => s.username === recipient
  );
  if (recipientSocket) {
    recipientSocket.emit('private message', { from: socket.username, message: msg });
  }
});



let activeUsers = [];

// On user connection
io.on('connection', (socket) => {
  activeUsers.push(socket.username); // Add user to the list
  io.emit('user list', activeUsers); // Emit updated user list to all clients

  // Listen for private messages
  socket.on('private message', (recipient, msg) => {
    const recipientSocket = Object.values(io.sockets.sockets).find(
      (s) => s.username === recipient
    );
    if (recipientSocket) {
      recipientSocket.emit('private message', { from: socket.username, message: msg });
    }
  });

  socket.on('disconnect', () => {
    activeUsers = activeUsers.filter((user) => user !== socket.username);
    io.emit('user list', activeUsers); // Update user list
  });
});

io.on('connection', (socket) => {
  // Send last 10 messages to the new user
  Message.find().sort({ timestamp: -1 }).limit(10).exec((err, messages) => {
    if (err) console.error('Error fetching messages:', err);
    messages.forEach((msg) => {
      socket.emit('chat message', { username: msg.username, message: msg.message });
    });
  });

  // Continue with the rest of the code...
});

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});