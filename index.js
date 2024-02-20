const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const env = require("dotenv");
const cors = require("cors");

env.config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const SECRET_KEY = process.env.SECRET_KEY;

app.use(cors());

//Models

//User Model
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    username: String,
    password: String,
  })
);

//Form Model
const Form = mongoose.model(
  "Form",
  new mongoose.Schema({
    email: String,
    phone: Number,
    title: String,
    note: String,
  })
);

//Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const verifyToken = (req, res, next) => {
  const token = req.header("authorization");

  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized: Invalid token" });
  }
};

//Routes
app.get("/", (req, res) => {
  res.status(200).json({
    Message: "Server is Live",
  });
});

app.post("/user/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log(username, password);
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post("/user/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log(username, password)
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, SECRET_KEY, {
      expiresIn: "48h",
    });
    res.json({ token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Get Forms
app.get("/form", verifyToken, async (req, res) => {
  try {
    console.log("form")
    const forms = await Form.find({});
    res.status(200).json({ forms: forms });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Add Form
app.post("/form/add", verifyToken, async (req, res) => {
  try {
    const { email, phone, title, note } = req.body;
    console.log(email, phone, title, note);
    const form = new Form({ email, phone, title, note });
    await form.save();
    res.status(201).json({ message: "Form added successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Update Form
app.put("/form/update/:id", verifyToken, async (req, res) => {
  try {
    const { email, phone, title, note } = req.body;
    console.log(email, phone, title, note);
    const formId = req.params.id;

    // Assuming you want to find the form by its ID
    const form = await Form.findById(formId);

    if (!form) {
      return res.status(404).json({ message: "Form not found" });
    }

    // Update the form properties only if they are provided in the request body
    if (email) {
      form.email = email;
    }

    if (phone) {
      form.phone = phone;
    }

    if (title) {
      form.title = title;
    }

    if (note) {
      form.note = note;
    }

    await form.save();

    res.json({ message: "Form updated successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.listen(PORT, async() => {
  //Connection to MongoDB
  await mongoose.connect(MONGO_URI);
  console.log(`Server is running on http://localhost:${PORT}`);
});
