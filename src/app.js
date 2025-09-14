// src/app.js
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

// ✅ Parse JSON requests
app.use(express.json({ limit: "16kb" }));

// ✅ Parse URL-encoded form data
app.use(express.urlencoded({ extended: true, limit: "16kb" }));

app.use(cookieParser());
// ✅ Enable CORS
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "*",
    credentials: true,
    methods: ["GET", "POST", "HEAD", "DELETE", "PUT", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ✅ Import routes
import healthCheckRouter from "./routes/healthCheck.routes.js";
import authRouter from "./routes/auth.routes.js";

// ✅ Use routes
app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/auth", authRouter);

// ✅ Base route
app.get("/", (req, res) => {
  res.send("Welcome to my Page!");
});

export default app;
