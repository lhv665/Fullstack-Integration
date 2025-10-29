const express = require("express");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());

// --- Demo users ---
const users = [
  { id: 1, username: "adminUser", password: "admin123", role: "Admin" },
  { id: 2, username: "modUser", password: "mod123", role: "Moderator" },
  { id: 3, username: "normalUser", password: "user123", role: "User" },
];

// --- Login Route ---
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Generate JWT token with role info
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// --- Middleware to verify token ---
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(403).json({ message: "Token missing" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });

    req.user = decoded; // attach decoded user info to request
    next();
  });
}

// --- Middleware to check role ---
function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied: Insufficient role" });
    }
    next();
  };
}

// --- Protected Routes ---
app.get("/admin", verifyToken, authorizeRoles("Admin"), (req, res) => {
  res.json({ message: "Welcome, Admin! You have full access.", user: req.user });
});

app.get("/moderator", verifyToken, authorizeRoles("Moderator", "Admin"), (req, res) => {
  res.json({ message: "Welcome, Moderator! You can manage users.", user: req.user });
});

app.get("/user", verifyToken, authorizeRoles("User", "Moderator", "Admin"), (req, res) => {
  res.json({ message: "Welcome, User! You can view your profile.", user: req.user });
});

// --- Start Server ---
app.listen(process.env.PORT, () => {
  console.log(`✅ Server running on http://localhost:${process.env.PORT}`);
});
