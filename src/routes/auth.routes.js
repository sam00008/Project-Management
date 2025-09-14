// src/routes/auth.routes.js
import { Router } from "express";
import { registerUser } from "../controller/auth.controllers.js";

const router = Router();

// Define your route
router.route("/register").post(registerUser);

// ✅ Export as default
export default router;
