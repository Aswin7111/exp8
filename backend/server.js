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
app.use(cors()); 
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


// --- === NEW: Booking Model (Database Schema) === ---
const BookingSchema = new mongoose.Schema({
  // This links the booking to a specific user
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User'
  },
  destinationName: {
    type: String,
    required: true,
    trim: true
  },
  price: {
    type: String,
    required: true,
  },
  bookedAt: {
    type: Date,
    default: Date.now
  }
});
const Booking = mongoose.model('Booking', BookingSchema);


// --- === NEW: Authentication Middleware === ---
// This function checks for the token in the request headers
const auth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token, authorization denied.' });
  }

  try {
    // Get token from header (e.g., "Bearer <token>")
    const token = authHeader.split(' ')[1];
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Add user from payload to the request object
    // Now all protected routes will have access to req.user
    req.user = decoded; 
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid.' });
  }
};


// --- API Routes ---

// 1. User Registration (Public)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { full_name, email, username, password } = req.body;
    if (!full_name || !email || !username || !password) {
      return res.status(400).json({ message: "Please fill in all fields." });
    }
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({ message: "Email is already registered." });
      }
      if (existingUser.username === username) {
        return res.status(400).json({ message: "Username is already taken." });
      }
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({
      full_name,
      email,
      username,
      password: hashedPassword
    });
    const savedUser = await newUser.save();
    const token = jwt.sign({ id: savedUser._id, username: savedUser.username }, JWT_SECRET, {
      expiresIn: '24h'
    });
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

// 2. User Login (Public)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) {
      return res.status(400).json({ message: "Please provide username/email and password." });
    }
    const user = await User.findOne({
      $or: [{ email: usernameOrEmail.toLowerCase() }, { username: usernameOrEmail.toLowerCase() }]
    });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials." });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials." });
    }
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, {
      expiresIn: '24h'
    });
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

// 3. Test route (Public)
app.get('/api', (req, res) => {
  res.json({ message: "Welcome to the Travel & Tourism API!" });
});


// --- === NEW: Booking Routes (Protected) === ---

// 4. Create a new Booking (Protected)
// We add the 'auth' middleware here.
// This route will not work unless a valid token is sent.
app.post('/api/bookings', auth, async (req, res) => {
  try {
    const { destinationName, price } = req.body;
    
    // req.user.id comes from the auth middleware
    const newBooking = new Booking({
      userId: req.user.id, 
      destinationName,
      price
    });

    const savedBooking = await newBooking.save();
    res.status(201).json(savedBooking);

  } catch (error) {
    console.error("Booking Error:", error);
    res.status(500).json({ message: "Server error while creating booking." });
  }
});

// 5. Get all bookings for the logged-in user (Protected)
app.get('/api/bookings', auth, async (req, res) => {
  try {
    // req.user.id comes from the auth middleware
    // This finds all bookings that match the logged-in user's ID
    const bookings = await Booking.find({ userId: req.user.id });
    
    res.status(200).json(bookings);

  } catch (error) {
    console.error("Get Bookings Error:", error);
    res.status(500).json({ message: "Server error while fetching bookings." });
  }
});


// --- Start Server ---
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

