const express = require("express");
const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const serverless = require("serverless-http");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const dynamo = new AWS.DynamoDB.DocumentClient({ region: "ap-south-1" });
const TABLE_NAME = "webData";

// Yahoo SMTP transporter
const transporter = nodemailer.createTransport({
    service: "yahoo",
    auth: {
        user: process.env.YAHOO_EMAIL,
        pass: process.env.YAHOO_PASSWORD
    }
});

// Helper functions
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000);
}

async function sendOTPEmail(toEmail, otpCode) {
    const mailOptions = {
        from: process.env.YAHOO_EMAIL,
        to: toEmail,
        subject: "Your OTP for Signup/Login",
        text: `Your OTP is ${otpCode}. It is valid for 5 minutes.`
    };
    await transporter.sendMail(mailOptions);
}

// ---------------- Routes ----------------
app.post("/signup", async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const otpCode = generateOTP();
        const otpExpiry = Date.now() + 5 * 60 * 1000;

        await dynamo.put({
            TableName: TABLE_NAME,
            Item: { email, password: hashedPassword, verified: false, otp: otpCode, otpExpiry }
        }).promise();

        await sendOTPEmail(email, otpCode);
        res.json({ message: "OTP sent to your email" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Signup failed" });
    }
});

app.post("/verify", async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await dynamo.get({ TableName: TABLE_NAME, Key: { email } }).promise();
        if (!user.Item) return res.status(404).json({ error: "User not found" });
        if (user.Item.verified) return res.status(400).json({ error: "Already verified" });

        if (user.Item.otp === Number(otp) && user.Item.otpExpiry > Date.now()) {
            await dynamo.update({
                TableName: TABLE_NAME,
                Key: { email },
                UpdateExpression: "SET verified = :v REMOVE otp, otpExpiry",
                ExpressionAttributeValues: { ":v": true }
            }).promise();
            return res.json({ message: "Verified successfully" });
        } else {
            return res.status(400).json({ error: "Invalid or expired OTP" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Verification failed" });
    }
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await dynamo.get({ TableName: TABLE_NAME, Key: { email } }).promise();
        if (!user.Item) return res.status(404).json({ error: "User not found" });
        if (!user.Item.verified) return res.status(400).json({ error: "User not verified" });

        const match = await bcrypt.compare(password, user.Item.password);
        if (!match) return res.status(401).json({ error: "Invalid password" });

        return res.json({ message: "Login successful" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Login failed" });
    }
});

app.post("/resend-otp", async (req, res) => {
    const { email } = req.body;
    try {
        const user = await dynamo.get({ TableName: TABLE_NAME, Key: { email } }).promise();
        if (!user.Item) return res.status(404).json({ error: "User not found" });
        if (user.Item.verified) return res.status(400).json({ error: "Already verified" });

        const otpCode = generateOTP();
        const otpExpiry = Date.now() + 5 * 60 * 1000;

        await dynamo.update({
            TableName: TABLE_NAME,
            Key: { email },
            UpdateExpression: "SET otp = :o, otpExpiry = :e",
            ExpressionAttributeValues: { ":o": otpCode, ":e": otpExpiry }
        }).promise();

        await sendOTPEmail(email, otpCode);
        res.json({ message: "OTP resent" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to resend OTP" });
    }
});

// ---------------- Export for Lambda ----------------
module.exports.handler = serverless(app);
