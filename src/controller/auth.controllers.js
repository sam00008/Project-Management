import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/api_Response.js";
import { ApiError } from "../utils/api-Error.js";
import { asyncHandler } from "../utils/async-handler.js";
import {
    emailVerificationMailgenContent,
    forgotPasswordMailgenContent,
    sendEmail,
} from "../utils/mail.js";
import jwt from "jsonwebtoken";
import { json } from "express";
import crypto from "crypto";


//Method for genrate Refresh and Access token
const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        const AccessToken = user.generateAccessToken();
        const RefreshToken = user.generateRefreshToken();

        user.refreshToken = RefreshToken;
        await user.save({ validateBeforeSave: false });
        return { AccessToken, RefreshToken };

    } catch (error) {
        throw new ApiError(
            500,
            "Something went wrong while genarating access token"
        );
    }
};

const registerUser = asyncHandler(async (req, res) => {
    // 1.receving the data 
    const { username, email, password, role } = req.body;
    // 2. validation of data later

    // 3. Check in DB if User already exists

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    });

    // 3.1 if user exist throw an error
    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists", []);
    }

    // 3.2 if user not exist then fill the define spaces like Access token
    const user = await User.create({
        email,
        password,
        username,
        isEmailVerified: false
    });

    // Now create the token 
    const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    user.EmailVerificationToken = hashedToken;
    user.EmailVerificationExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });
    

    await sendEmail({
        email: user?.email,
        subject: "Please verify your email",
        mailgenContent: emailVerificationMailgenContent(
            user.username,
            `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`)
    });

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken -EmailVerificationToken -EmailVerificationExpiry",
    );

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering a user");
    }

    return res
        .status(201)
        .json(
            new ApiResponse(
                200,
                { user: createdUser },
                "User registered succesfully and verificatio email has been send on your email",
            ),
        );

});

const login = asyncHandler(async (req, res) => {
    const { email, username, password } = req.body;

    if (!email) {
        throw new ApiError(400, "Username is email is required");
    }

    const user = await User.findOne({ email });
    if (!user) {
        throw new ApiError(400, "User does not exists");
    }

    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
        throw new ApiError(400, "Password is incorrect");
    }

    const { AccessToken, RefreshToken } = await generateAccessAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken -EmailVerificationToken -EmailVerificationExpiry",
    );

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .cookie("accessToken", AccessToken, options)
        .cookie("refreshToken", RefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken: AccessToken,
                    refreshToken: RefreshToken
                },
                "User logged in successfully"
            )
        )
});

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: "" // ✅ clears the token
            }
        },
        { new: true }
    );

    const options = {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
    };

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                req.user,
                "Current User fetched Succesfully"
            )
        );
});

const verifyEmail = asyncHandler(async (req, res) => {
    const { verificationToken } = req.params;

    if (!verificationToken) {
        throw new ApiError(400, "Email Verification token is missing");
    }

    const hashedToken = crypto
        .createHash("sha256")
        .update(verificationToken)
        .digest("hex");

    const user = await User.findOne({
        EmailVerificationToken: hashedToken,
        EmailVerificationExpiry: { $gt: Date.now() }
    });

    if (!user) {
        throw new ApiError(400, "Token is invalid or expired");
    }

    user.EmailVerificationToken = undefined;
    user.EmailVerificationExpiry = undefined;

    user.isEmailVerified = true;
    await user.save({ validateBeforeSave: false });


    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                {
                    isEmailVerified: true
                },
                "Email is verified"
            )
        )
});

const resendEmailVerification = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user?._id);

    if (!user) {
        throw new ApiError(404, "User does not exist");
    }

    if (user.isEmailVerified) {
        throw new ApiError(409, "Email is already verified");
    }

    // ✅ Use generateTemporaryToken to create verification token
    const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    // Save hashed token and expiry in the DB
    user.EmailVerificationToken = hashedToken;
    user.EmailVerificationExpiry = tokenExpiry;

    await user.save({ validateBeforeSave: false });

    // Send email with unHashedToken
    await sendEmail({
        email: user.email,
        subject: "Please verify your email",
        mailgenContent: emailVerificationMailgenContent(
            user.username,
            `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
        )
    });

    return res.status(200).json({
        message: "Verification email sent successfully",
        success: true
    });
});


const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefresToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefresToken) {
        throw new ApiError(401, "Unauthorized access");
    }

    try {
        // Verify the refresh token
        const decodedToken = jwt.verify(incomingRefresToken, process.env.REFRESH_TOKEN_SECRET);
        

        // Find user in DB
        const user = await User.findById(decodedToken?._id);
       
        if (!user) {
            throw new ApiError(401, "Invalid refresh token");
        }

        // Check if the token matches DB
        
        if (incomingRefresToken !== user.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or does not match");
        }

        // Generate new tokens
        const { accessToken, refreshToken: newRefreshToken } = await generateAccessAndRefreshToken(user._id);

        // Save the new refresh token
        user.refreshToken = newRefreshToken;
        await user.save({ validateBeforeSave: false });

        const options = {
            httpOnly: true,
            secure: true,
        };

        // Send response
        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed successfully"
                )
            );
    } catch (error) {
        throw new ApiError(401, "Invalid refresh token");
    }
});


const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;

    // Find the user
    const user = await User.findOne({ email });
    if (!user) throw new ApiError(404, "User does not exist");

    // Generate temporary token
    const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    // Save hashed token & expiry
    user.forgotPasswordToken = hashedToken;
    user.forgotPasswordExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    // Send the unhashed token in email (or response for testing)
    await sendEmail({
        email: user.email,
        subject: "Reset your password",
        mailgenContent: forgotPasswordMailgenContent(
            user.username,
            `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`
        )
    });

    return res.status(200).json({
        message: "Password reset email sent successfully",
        resetToken: unHashedToken, // Only for testing, remove in production
        success: true
    });
});


const resetForgotPassword = asyncHandler(async (req, res) => {
    const { resetToken } = req.params; // token from URL
    const { newPassword } = req.body;

    // Hash the token to match DB
    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    // Find user with matching token & not expired
    const user = await User.findOne({
        forgotPasswordToken: hashedToken,
        forgotPasswordExpiry: { $gt: Date.now() }
    });

    if (!user) throw new ApiError(489, "Token is invalid or expired");

    // Reset password & clear token fields
    user.password = newPassword;
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;

    await user.save(); // pre-save hook hashes password

    return res.status(200).json({
        message: "Password reset successfully",
        success: true
    });
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user?._id);

    const isPasswordValid = await user.isPasswordCorrect(oldPassword);
    if (!isPasswordValid) {
        throw new ApiError(400, "Invalid old Password");
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                {},
                "Password is changed successfully"
            )
        );

});


export {
    registerUser,
    login,
    logoutUser,
    getCurrentUser,
    verifyEmail,
    resendEmailVerification,
    refreshAccessToken,
    forgotPassword,
    resetForgotPassword,
    changeCurrentPassword
};