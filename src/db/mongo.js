// src/db/mongo.js
import mongoose from "mongoose";

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGO_URL;
    console.log("🔹 Mongo URI from env:", mongoURI); // Debugging

    if (!mongoURI) {
      throw new Error("MongoDB URI is missing. Please check your .env file.");
    }

    await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log("✅ MongoDB connected successfully!");
  } catch (error) {
    console.error("❌ MongoDB connection error:", error.message);
    process.exit(1);
  }
};

export default connectDB;
