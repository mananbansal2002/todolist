require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors());
// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI || 'mongodb://localhost:27017/todolist', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error(err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

// Task Schema
const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  desc: { type: String, default: '' },
  date: { type: Date, default: Date.now },
  status: {
    type: String,
    enum: ['pending', 'in progress', 'completed'],
    default: 'pending',
  },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});
const Task = mongoose.model('Task', taskSchema);

// JWT Middleware
const auth = (req, res, next) => {
  console.log(req.header);
  const token = req.header('Authorization').split(' ')[1];
  if (!token) return res.status(401).send('Access Denied');
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid Token');
  }
};

// --- Auth Routes ---

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  const existing = await User.findOne({ username });
  if (existing) return res.status(400).send('User already exists');
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed });
  await user.save();
  res.send('User registered');
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).send('Invalid credentials');
  const token = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET || 'secretkey'
  );
  res.json({ token });
});

// --- Task Routes ---

// Create Task
app.post('/api/tasks', auth, async (req, res) => {
  const { title, desc, date, status } = req.body;
  const task = new Task({
    title,
    desc,
    date,
    status,
    userId: req.user.id,
  });
  await task.save();
  res.json(task);
});

// Get All Tasks
app.get('/api/tasks', auth, async (req, res) => {
  const tasks = await Task.find({ userId: req.user.id }).sort({ date: -1 });
  res.json(tasks);
});

// Update Task
app.put('/api/tasks/:id', auth, async (req, res) => {
  const { title, desc, date, status } = req.body;
  const task = await Task.findOneAndUpdate(
    { _id: req.params.id, userId: req.user.id },
    { title, desc, date, status },
    { new: true }
  );
  if (!task) return res.status(404).send('Task not found');
  res.json(task);
});

// Delete Task
app.delete('/api/tasks/:id', auth, async (req, res) => {
  const deleted = await Task.findOneAndDelete({
    _id: req.params.id,
    userId: req.user.id,
  });
  if (!deleted) return res.status(404).send('Task not found');
  res.send('Task deleted');
});

app.use(express.json());
// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
