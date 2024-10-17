const express = require("express");
const https = require("https");
const fs = require("fs");
const db = require("./db/connect");
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const hpp = require("hpp");
require("dotenv").config();
const securityConfig = require("./config/security.config");
const authRouter = require("./routes/auth.route");
const servicesRouter = require("./routes/services.route");

const app = express();

// Security Middleware


app.use(cors({
  origin: process.env.FRONTEND_URL,
  optionsSuccessStatus: 200
}));
app.use(hpp());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use("/api", limiter);

// Apply custom security configurations
securityConfig(app);

// Standard Middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Routes
app.use("/api/auth", authRouter);
app.use("/api/services", servicesRouter);
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// SSL options
const options = {
  key: fs.readFileSync(path.join(__dirname, 'key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'cert.pem'))
};

// Connect to MongoDB and start the HTTPS Server
const port = process.env.PORT || 5000;
const start = async () => {
  try {
    await db(process.env.MONGODB_URI);
    https.createServer(options, app).listen(port, () => 
      console.log(`HTTPS Server listening on port ${port}...`)
    );
  } catch (error) {
    console.log(error);
  }
};

start();
