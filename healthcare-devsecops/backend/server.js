require("dotenv").config();
const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8000;

// Serve UI (index.html automatically)
app.use(express.static(__dirname));

// Read users
const getUsers = () => {
  const data = fs.readFileSync(path.join(__dirname, "users.json"));
  return JSON.parse(data);
};

// Save users
const saveUsers = (users) => {
  fs.writeFileSync(
    path.join(__dirname, "users.json"),
    JSON.stringify(users, null, 2)
  );
};

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;

  let users = getUsers();

  const existingUser = users.find((u) => u.email === email);
  if (existingUser) {
    return res.status(400).json({ msg: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({ email, password: hashedPassword });
  saveUsers(users);

  res.json({ msg: "User registered securely" });
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  let users = getUsers();

  const user = users.find((u) => u.email === email);
  if (!user) {
    return res.status(400).json({ msg: "User not found" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ msg: "Invalid credentials" });
  }

  const token = jwt.sign({ email }, process.env.JWT_SECRET, {
    expiresIn: "1h"
  });

  res.json({ token });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});