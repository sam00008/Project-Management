// src/routes/auth.routes.js
import { Router } from "express";
import { forgotPassword, login, logoutUser, refreshAccessToken, registerUser, verifyEmail, resetForgotPassword, getCurrentUser, changeCurrentPassword, resendEmailVerification } from "../controller/auth.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import { userChangeCurrentPasswordValidator, userForgotPasswordValidator, userLoginValidator, userRegisterValidator, userResetForgotPasswordValidator } from "../validators/index.js";
import { verifyJwt } from "../middlewares/auth.middleware.js";
const router = Router();

// Define your route
// unsecured routes
router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, login);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/forgot-password").post(userForgotPasswordValidator(), validate, forgotPassword);
router.route("/reset-password/:resetToken").post(userResetForgotPasswordValidator(), validate, resetForgotPassword)

// secured routes
router.route("/logout").post(verifyJwt, logoutUser);
router.route("/current-user").post(verifyJwt, getCurrentUser);
router.route("/change-password").post(verifyJwt, userChangeCurrentPasswordValidator(), validate, changeCurrentPassword);
router.route("/resend-email-verification").post(verifyJwt,resendEmailVerification);
// ✅ Export as default
export default router;
