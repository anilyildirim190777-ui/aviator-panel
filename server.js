require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
app.use(express.static("public"));
app.use(cors());
app.use(bodyParser.json());

// ===== DB =====
mongoose.connect(process.env.MONGO_URL);
// ===== MODEL =====
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  isAdmin: { type: Boolean, default: false },
  isApproved: { type: Boolean, default: false },
  isPremium: { type: Boolean, default: false },
  premiumEndDate: Date,
  isBanned: { type: Boolean, default: false }
});

const User = mongoose.model("User", userSchema);

// ===== AUTH =====
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const payload = jwt.verify(token, "SECRET");
    req.userId = payload.id;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

async function adminOnly(req, res, next) {
  const u = await User.findById(req.userId);
  if (!u || !u.isAdmin) return res.status(403).json({ message: "Forbidden" });
  next();
}

// ===== REGISTER =====
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  const user = new User({
    username,
    email,
    password: hashed
  });

  await user.save();
  res.json({ message: "Kayıt başarılı, admin onayı bekleniyor" });
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.json({ message: "Kullanıcı yok" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ message: "Şifre yanlış" });

  if (!user.isApproved)
    return res.json({ message: "Admin onayı bekleniyor" });

  const token = jwt.sign({ id: user._id }, "SECRET");

  res.json({ token, user });
});

// ===== ADMIN LOGIN =====
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.json({ message: "Kullanıcı yok" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ message: "Şifre yanlış" });

  if (!user.isAdmin) return res.json({ message: "Admin değil" });

  const token = jwt.sign({ id: user._id }, "SECRET");

  res.json({ token });
});

// ===== ADMIN SIFRE DEGISTIR =====
app.post("/admin/change-password", auth, adminOnly, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const admin = await User.findById(req.userId);

  const ok = await bcrypt.compare(oldPassword, admin.password);
  if (!ok) return res.json({ message: "Eski şifre yanlış" });

  admin.password = await bcrypt.hash(newPassword, 10);
  await admin.save();

  res.json({ message: "Şifre değişti" });
});

// ===== USERS =====
app.get("/users", auth, adminOnly, async (req, res) => {
  const users = await User.find();
  res.json(users);
});

// ===== APPROVE =====
app.post("/approve/:id", auth, adminOnly, async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { isApproved: true });
  res.json({ message: "Onaylandı" });
});

// ===== BAN =====
app.post("/ban/:id", auth, adminOnly, async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { isBanned: true });
  res.json({ message: "Banlandı" });
});

// ===== PREMIUM =====
app.post("/premium/:id", auth, adminOnly, async (req, res) => {
  const days = req.body.days || 30;
  const end = new Date();
  end.setDate(end.getDate() + days);

  await User.findByIdAndUpdate(req.params.id, {
    isPremium: true,
    premiumEndDate: end
  });

  res.json({ message: "Premium verildi" });
});

// ===== ANALIZ =====
app.post("/analyze", auth, (req, res) => {
  const { lastResults } = req.body;

  const avg = lastResults.reduce((a, b) => a + b, 0) / lastResults.length;

  const decision = avg > 2 ? "AL" : "ALMA";
  const risk = avg > 2 ? "DÜŞÜK" : "YÜKSEK";

  res.json({
    decision,
    risk,
    average: avg.toFixed(2)
  });
});

// ===== SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server çalışıyor 🚀"));