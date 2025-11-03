import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();

// --- Middleware ---
// Use CORS to allow requests from any origin.
// This is necessary for your index.html to talk to the backend.
app.use(cors()); 
// Parse incoming JSON requests
app.use(express.json());

// --- Environment Variables ---
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO_URI || !JWT_SECRET) {
  console.error("FATAL ERROR: MONGO_URI and JWT_SECRET must be defined in .env file");
  process.exit(1);
}

// --- Database Connection ---
mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB connected successfully."))
  .catch(err => console.error("MongoDB connection error:", err));

// --- User Model (Database Schema) ---
const UserSchema = new mongoose.Schema({
  full_name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

// Add indexes for faster lookups
UserSchema.index({ email: 1 });
UserSchema.index({ username: 1 });

const User = mongoose.model('User', UserSchema);


// --- API Routes ---

// 1. User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { full_name, email, username, password } = req.body;

    // Basic validation
    if (!full_name || !email || !username || !password) {
      return res.status(400).json({ message: "Please fill in all fields." });
    }

    // Check for duplicate username or email
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({ message: "Email is already registered." });
      }
      if (existingUser.username === username) {
        return res.status(400).json({ message: "Username is already taken." });
      }
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create and save the new user
    const newUser = new User({
      full_name,
      email,
      username,
      password: hashedPassword
    });

    const savedUser = await newUser.save();

    // Create a JWT token
    const token = jwt.sign({ id: savedUser._id, username: savedUser.username }, JWT_SECRET, {
      expiresIn: '24h' // Token expires in 24 hours
    });

    // Send token and success message back
    res.status(201).json({
      token,
      message: "User registered successfully!",
      user: {
        id: savedUser._id,
        full_name: savedUser.full_name,
        username: savedUser.username
      }
    });

  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({ message: "Server error during registration." });
  }
});

// 2. User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;

    // Basic validation
    if (!usernameOrEmail || !password) {
      return res.status(400).json({ message: "Please provide username/email and password." });
    }

    // Find the user by either username or email
    const user = await User.findOne({
      $or: [{ email: usernameOrEmail.toLowerCase() }, { username: usernameOrEmail.toLowerCase() }]
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials." });
    }

    // Check if the password is correct
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials." });
    }

    // Create a JWT token
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, {
      expiresIn: '24h' // Token expires in 24 hours
    });

    // Send token and success message back
    res.status(200).json({
      token,
      message: "Login successful!",
      user: {
        id: user._id,
        full_name: user.full_name,
        username: user.username
      }
    });

  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server error during login." });
  }
});

// Test route
app.get('/api', (req, res) => {
  res.json({ message: "Welcome to the Travel & Tourism API!" });
});


// --- Start Server ---
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});