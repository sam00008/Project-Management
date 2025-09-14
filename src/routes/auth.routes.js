// src/routes/auth.routes.js
import { Router } from "express";
import { login, registerUser } from "../controller/auth.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import { userLoginValidator, userRegisterValidator } from "../validators/index.js";
const router = Router();

// Define your route
router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate,login);

// ✅ Export as default
export default router;
