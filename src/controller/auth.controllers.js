import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/api_Response.js";
import { ApiError } from "../utils/api-Error.js";
import { asyncHandler } from "../utils/async-handler.js";
import {
    emailVerificationMailgenContent,
    forgotPasswordMailgenContent,
    sendEmail,
} from "../utils/mail.js";


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

export { registerUser };