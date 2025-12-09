require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const axios = require("axios");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 5000;
// Ye code index.js mein add karo
app.get('/', (req, res) => {
  res.send("Hello! Server is Running (Zobbly)");
});// Ye code index.js mein add karo
app.get('/', (req, res) => {
  res.send("Hello! Server is Running (Zobbly)");
});
// 📁 Create Uploads Folder
if (!fs.existsSync("./uploads")) {
    fs.mkdirSync("./uploads");
}

// ------------------- MIDDLEWARE (CORS FIXED) -------------------
app.use(express.json());

// ✅ FIX: Sabko allow karne wala CORS (Connection Problem Solved)
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "x-auth-token"]
}));

app.use("/uploads", express.static("uploads"));

// ------------------- DATABASE CONNECT -------------------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch((err) => console.log("❌ MongoDB Connection Error:", err));

// ======================= SCHEMAS =======================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  headline: { type: String, default: "Zobbly User" },
  photo: { type: String, default: "" },
  otp: { type: String }, otpExpires: { type: Date }, 
  experience: [{ company: String, role: String, year: String }],
  blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }]
});
const User = mongoose.model("User", userSchema);

const notificationSchema = new mongoose.Schema({
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, 
    type: { type: String, required: true },
    message: { type: String },
    relatedId: { type: String },
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
const Notification = mongoose.model("Notification", notificationSchema);

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    content: { type: String, required: true },
    image: { type: String }, 
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], 
    comments: [{ 
        userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        userName: String,
        text: String,
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model("Post", postSchema);

const messageSchema = new mongoose.Schema({
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    receiverId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    content: { type: String }, 
    type: { type: String, default: "text" }, 
    fileUrl: { type: String }, 
    timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model("Message", messageSchema);

// ------------------- MULTER -------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

const verifyToken = (req, res, next) => {
  const token = req.header("x-auth-token");
  if (!token) return res.status(401).json({ error: "Access Denied" });
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) { res.status(400).json({ error: "Invalid Token" }); }
};

// ======================= API ROUTES =======================

// A. Follow/Unfollow
app.put("/api/user/follow/:id", verifyToken, async (req, res) => {
    try {
        const targetId = req.params.id; const myId = req.user.id;      
        if(targetId === myId) return res.status(400).json({error: "Cannot follow yourself"});
        const targetUser = await User.findById(targetId);
        const me = await User.findById(myId);
        let status = "";
        if(targetUser.followers.includes(myId)) {
            targetUser.followers.pull(myId); me.following.pull(targetId); status = "unfollowed";
        } else {
            targetUser.followers.push(myId); me.following.push(targetId); status = "followed";
            await new Notification({ recipient: targetId, sender: myId, type: 'follow', message: `${me.name} started following you.`, relatedId: myId }).save();
        }
        await targetUser.save(); await me.save();
        res.json({ status: status, followersCount: targetUser.followers.length });
    } catch(e) { res.status(500).json({error: "Error"}); }
});

// B. Profile
app.get("/api/user/profile/:id", async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select("-password -otp");
        const posts = await Post.find({ userId: req.params.id }).sort({ createdAt: -1 });
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json({ user, posts });
    } catch (e) { res.status(500).json({ error: "Error" }); }
});

// C. Notifications
app.get("/api/notifications", verifyToken, async (req, res) => {
    try { const notifs = await Notification.find({ recipient: req.user.id }).populate("sender", "name photo").sort({ createdAt: -1 }); res.json(notifs); } catch(e) { res.status(500).json({error: "Error"}); }
});

// D. Chat
app.get("/api/chat/conversations", verifyToken, async (req, res) => {
    try {
        const messages = await Message.find({ $or: [{ senderId: req.user.id }, { receiverId: req.user.id }] })
            .populate("senderId", "name photo email").populate("receiverId", "name photo email").sort({ timestamp: -1 });
        const usersMap = new Map();
        messages.forEach(msg => {
            const otherUser = msg.senderId._id.toString() === req.user.id ? msg.receiverId : msg.senderId;
            if(!usersMap.has(otherUser._id.toString())) {
                usersMap.set(otherUser._id.toString(), {
                    _id: otherUser._id, name: otherUser.name, photo: otherUser.photo,
                    lastMsg: msg.content || (msg.type === 'image' ? 'Sent an image' : 'Sent a video'), time: msg.timestamp
                });
            }
        });
        res.json(Array.from(usersMap.values()));
    } catch(e) { res.status(500).json({error: "Error"}); }
});

// Feed
app.post("/api/posts/create", verifyToken, upload.single("postImage"), async (req, res) => {
    try {
        const img = req.file ? `https://zobbly.onrender.com/uploads/${req.file.filename}` : "";
        const newPost = new Post({ userId: req.user.id, content: req.body.content, image: img }); 
        await newPost.save();
        const user = await User.findById(req.user.id);
        const notifications = user.followers.map(followerId => ({
            recipient: followerId, sender: req.user.id, type: 'post',
            message: `${user.name} added a new post.`, relatedId: newPost._id
        }));
        if(notifications.length > 0) await Notification.insertMany(notifications);
        res.json(newPost);
    } catch(e) { res.status(500).json({error: "Error"}); }
});

app.get("/api/posts", async (req, res) => { const posts = await Post.find().populate("userId", "name photo headline").sort({ createdAt: -1 }); res.json(posts); });
app.get("/api/my-posts", verifyToken, async (req, res) => { const posts = await Post.find({ userId: req.user.id }).sort({ createdAt: -1 }); res.json(posts); });
app.delete("/api/posts/:id", verifyToken, async (req, res) => { await Post.findOneAndDelete({ _id: req.params.id, userId: req.user.id }); res.json({ message: "Deleted" }); });
app.put("/api/posts/like/:id", verifyToken, async (req, res) => {
    const post = await Post.findById(req.params.id);
    if(post.likes.includes(req.user.id)) post.likes.pull(req.user.id); else post.likes.push(req.user.id);
    await post.save(); res.json(post.likes);
});
app.post("/api/posts/comment/:id", verifyToken, async (req, res) => {
    const user = await User.findById(req.user.id); const post = await Post.findById(req.params.id);
    post.comments.push({ userId: user._id, userName: user.name, text: req.body.text }); await post.save(); res.json(post.comments);
});

// Chat Details
app.get("/api/search", verifyToken, async (req, res) => {
    const users = await User.find({ name: { $regex: req.query.q, $options: "i" }, _id: { $ne: req.user.id } }).select("name photo email"); res.json(users);
});
app.post("/api/messages", verifyToken, async (req, res) => {
    try {
        await new Message({ senderId: req.user.id, receiverId: req.body.receiverId, content: req.body.content }).save(); 
        await new Notification({ recipient: req.body.receiverId, sender: req.user.id, type: 'message', message: `New message`, relatedId: req.user.id }).save();
        res.json({ message: "Sent" });
    } catch(e) { res.status(500).json({error: "Error"}); }
});
app.post("/api/messages/upload", verifyToken, upload.single("chatFile"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file" });
    const url = `https://zobbly.onrender.com/uploads/${req.file.filename}`;
    const type = req.file.mimetype.startsWith("video") ? "video" : "image";
    await new Message({ senderId: req.user.id, receiverId: req.body.receiverId, content: "", type, fileUrl: url }).save();
    res.json({ message: "File Sent" });
});
app.delete("/api/messages/clear/:otherId", verifyToken, async (req, res) => {
    await Message.deleteMany({ $or: [{ senderId: req.user.id, receiverId: req.params.otherId }, { senderId: req.params.otherId, receiverId: req.user.id }] });
    res.json({ message: "Cleared" });
});
app.delete("/api/messages/:id", verifyToken, async (req, res) => { await Message.findByIdAndDelete(req.params.id); res.json({ message: "Deleted" }); });
app.get("/api/messages/:otherId", verifyToken, async (req, res) => {
    const msgs = await Message.find({ $or: [{ senderId: req.user.id, receiverId: req.params.otherId }, { senderId: req.params.otherId, receiverId: req.user.id }] }).sort({ timestamp: 1 });
    res.json(msgs);
});

// JOB SEARCH (Proxy)
app.get("/api/jobs/mantiks", async (req, res) => {
    try { const options = { method: 'GET', url: 'https://jsearch.p.rapidapi.com/search', params: { query: `${req.query.what} in India`, page: '1', num_pages: '1' }, headers: { 'X-RapidAPI-Key': process.env.RAPID_API_KEY, 'X-RapidAPI-Host': 'jsearch.p.rapidapi.com' } };
    const response = await axios.request(options); res.json({ source: "JSearch", data: response.data.data }); } catch (err) { res.json({ source: "System", data: [], error: "Search failed" }); }
});
app.get("/api/jobs/mantiks/company", async (req, res) => {
    try { const options = { method: 'GET', url: 'https://jsearch.p.rapidapi.com/search', params: { query: `${req.query.name} jobs in India`, page: '1', num_pages: '1' }, headers: { 'X-RapidAPI-Key': process.env.RAPID_API_KEY, 'X-RapidAPI-Host': 'jsearch.p.rapidapi.com' } };
    const response = await axios.request(options); res.json({ source: "JSearch", data: response.data.data }); } catch (err) { res.json({ source: "System", data: [], error: "No data found" }); }
});
app.get("/api/jobs/adzuna", async (req, res) => {
    try { const url = `https://api.adzuna.com/v1/api/jobs/in/search/1?app_id=${process.env.ADZUNA_APP_ID}&app_key=${process.env.ADZUNA_APP_KEY}&results_per_page=20&what=${req.query.what}&where=${req.query.where}`; const response = await axios.get(url); res.json({ source: "Adzuna", data: response.data.results }); } catch (err) { res.status(500).json({ error: "Error" }); }
});
app.get("/api/jobs/jsearch", async (req, res) => {
    try { const options = { method: 'GET', url: 'https://jsearch.p.rapidapi.com/search', params: { query: req.query.query, page: '1', num_pages: '1' }, headers: { 'X-RapidAPI-Key': process.env.RAPID_API_KEY, 'X-RapidAPI-Host': 'jsearch.p.rapidapi.com' } }; const response = await axios.request(options); res.json({ source: "JSearch", data: response.data.data }); } catch (err) { res.status(500).json({ error: "Error" }); }
});
app.get("/api/jobs/google", async (req, res) => {
    try { const url = `https://serpapi.com/search.json?engine=google_jobs&q=${req.query.q}&location=${req.query.location}&api_key=${process.env.SERP_API_KEY}`; const response = await axios.get(url); res.json({ source: "Google", data: response.data.jobs_results }); } catch (err) { res.status(500).json({ error: "Error" }); }
});

// AUTH & OTP
app.post("/api/register", async (req, res) => {
  try { const { name, email, password } = req.body; if(await User.findOne({ email })) return res.status(400).json({ error: "Exists" }); const hash = await bcrypt.hash(password, 10); await new User({ name, email, password: hash }).save(); res.json({ message: "Registered" }); } catch (err) { res.status(500).json({ error: "Server Error" }); }
});
app.post("/api/login", async (req, res) => {
  try { const { email, password } = req.body; const user = await User.findOne({ email }); if(!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({error: "Invalid"}); const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET); res.json({ token, user: { _id: user._id, name: user.name, email: user.email, photo: user.photo, blockedUsers: user.blockedUsers } }); } catch (err) { res.status(500).json({ error: "Server Error" }); }
});

// ✅ OTP SENDING (BREVO API)
app.post("/api/send-otp", async (req, res) => {
  try { 
      const { email, type } = req.body; 
      const user = await User.findOne({ email }); 
      if (!user) return res.status(404).json({ error: "User not found" }); 

      const otpCode = Math.floor(100000 + Math.random() * 900000).toString(); 
      user.otp = otpCode; user.otpExpires = Date.now() + 10 * 60 * 1000; 
      await user.save(); 

      await axios.post("https://api.brevo.com/v3/smtp/email", {
        sender: { name: "Zobbly App", email: process.env.SENDER_EMAIL },
        to: [{ email: email }],
        subject: "Verification Code",
        htmlContent: `<p>Your OTP code is: <b>${otpCode}</b></p>`
      }, {
        headers: { "accept": "application/json", "api-key": process.env.BREVO_API_KEY, "content-type": "application/json" }
      });

      console.log("✅ OTP Sent via API to:", email);
      res.json({ message: "OTP Sent" }); 
  } catch (err) { 
      console.log("❌ Brevo Error:", err.message);
      res.status(500).json({ error: "Email failed" }); 
  }
});

app.post("/api/verify-otp", async (req, res) => {
  try { const { email, otp } = req.body; const user = await User.findOne({ email }); if (!user || user.otp !== otp) return res.status(400).json({ error: "Invalid" }); res.json({ message: "Verified" }); } catch (err) { res.status(500).json({ error: "Server Error" }); }
});
app.post("/api/reset-password", async (req, res) => {
  try { const { email, newPassword } = req.body; const user = await User.findOne({ email }); const hash = await bcrypt.hash(newPassword, 10); user.password = hash; user.otp = undefined; await user.save(); res.json({ message: "Updated" }); } catch (err) { res.status(500).json({ error: "Server Error" }); }
});
app.put("/api/user/update", verifyToken, async (req, res) => { try { await User.findByIdAndUpdate(req.user.id, { name: req.body.name, headline: req.body.headline }); res.json({ message: "Updated" }); } catch(e) { res.status(500).json({error:"Error"}); } });
app.delete("/api/user/delete", verifyToken, async (req, res) => { try { await User.findByIdAndDelete(req.user.id); await Post.deleteMany({ userId: req.user.id }); await Message.deleteMany({ $or: [{ senderId: req.user.id }, { receiverId: req.user.id }] }); res.json({ message: "Deleted" }); } catch(e) { res.status(500).json({error:"Error"}); } });
app.get("/api/user/backup", verifyToken, async (req, res) => { try { const user = await User.findById(req.user.id); const posts = await Post.find({ userId: req.user.id }); const messages = await Message.find({ $or: [{ senderId: req.user.id }, { receiverId: req.user.id }] }); res.json({ user, posts, messages }); } catch(e) { res.status(500).json({error:"Error"}); } });
app.put("/api/user/block/:id", verifyToken, async (req, res) => { try { const user = await User.findById(req.user.id); const targetId = new mongoose.Types.ObjectId(req.params.id); if (user.blockedUsers.includes(targetId)) { user.blockedUsers.pull(targetId); res.json({ message: "Unblocked", status: "unblocked" }); } else { user.blockedUsers.push(targetId); res.json({ message: "Blocked", status: "blocked" }); } await user.save(); } catch(e) { res.status(500).json({error:"Error"}); } });
app.post("/api/user/add-experience", verifyToken, async (req, res) => { await User.findByIdAndUpdate(req.body.userId, { $push: { experience: req.body.experienceData } }); res.json({ message: "Added" }); });
app.put("/api/user/experience/:expId", verifyToken, async (req, res) => { const user = await User.findById(req.user.id); const exp = user.experience.id(req.params.expId); if(exp){ exp.company = req.body.company; exp.role = req.body.role; exp.year = req.body.year; await user.save(); res.json({ message: "Updated" }); } });
app.delete("/api/user/experience/:expId", verifyToken, async (req, res) => { const user = await User.findById(req.user.id); user.experience.pull(req.params.expId); await user.save(); res.json({ message: "Deleted" }); });
app.post("/api/user/upload-photo", verifyToken, upload.single("photo"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file" });
    const url = `https://zobbly.onrender.com/uploads/${req.file.filename}`;
    await User.findByIdAndUpdate(req.user.id, { photo: url }); res.json({ photoUrl: url });
});

app.listen(PORT, () => console.log(`🚀 Zobbly Server Running on Port ${PORT}`));
