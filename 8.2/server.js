const express = require("express");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());

// --- Hardcoded user for demo ---
const user = {
  id: 1,
  username: "testuser",
  password: "password123",
};

// --- Login Route ---
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Validate credentials
  if (username === user.username && password === user.password) {
    // Create token
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

// --- Middleware to verify token ---
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Extract Bearer token

  if (!token) {
    return res.status(403).json({ message: "Token missing" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    req.user = decoded; // Save user info from token
    next();
  });
}

// --- Protected Route ---
app.get("/protected", verifyToken, (req, res) => {
  res.json({
    message: "Welcome to the protected route!",
    user: req.user,
  });
});

// --- Start Server ---
app.listen(process.env.PORT, () => {
  console.log(`✅ Server running on http://localhost:${process.env.PORT}`);
});
