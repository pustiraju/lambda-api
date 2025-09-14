const express = require("express");
const AWS = require("aws-sdk");
const serverless = require("serverless-http");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const dynamo = new AWS.DynamoDB.DocumentClient();
const USERS_TABLE = "webData";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// --- Nodemailer setup ---
const transporter = nodemailer.createTransport({
  service: "yahoo",
  auth: {
    user: process.env.YAHOO_EMAIL,
    pass: process.env.YAHOO_PASSWORD,
  },
});

async function sendMail(to, subject, text) {
  const mailOptions = {
    from: process.env.YAHOO_EMAIL,
    to,
    subject,
    text,
  };
  return transporter.sendMail(mailOptions);
}

// --- Signup with OTP ---
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  console.log("Received signup request:", { name, email, password });
  

 const existingUser = await dynamodb
      .get({
        TableName: "webData",
        Key: { email }, // email is partition key
      })
      .promise();

    if (existingUser.Item) {
      return res.status(400).json({ error: "User already exists" });
    }

  // const hashedPassword = await bcrypt.hash(password, 10);
  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP

  await dynamo.put({
      TableName: USERS_TABLE,
      Item: {
        name,
        email,
        password,
        createdAt: new Date().toISOString(),
        verified: false
      },
      ConditionExpression: "attribute_not_exists(email)" // prevents overwriting existing user
    }).promise();

  try {
    await sendMail(email, "Your OTP Code", `Your OTP is: ${otp}`);
  } catch (err) {
    console.error("Email error:", err);
  }

  res.json({ message: "Signup successful, check your email for OTP" });
});

// --- Verify OTP ---
app.post("/verify-otp", (req, res) => {
  const { username, otp } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) return res.status(400).json({ error: "User not found" });
  if (user.verified) return res.json({ message: "Already verified" });

  if (user.otp === otp) {
    user.verified = true;
    delete user.otp; // remove OTP after success
    return res.json({ message: "OTP verified, you can now log in" });
  } else {
    return res.status(400).json({ error: "Invalid OTP" });
  }
});

// --- Login ---
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) return res.status(400).json({ error: "User not found" });
  if (!user.verified) return res.status(400).json({ error: "Please verify your email first" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Invalid password" });

  const token = jwt.sign({ username }, "SECRET_KEY", { expiresIn: "1h" });
  res.json({ message: "Login successful", token });
});

// --- Export for Lambda ---
module.exports.handler = serverless(app);

