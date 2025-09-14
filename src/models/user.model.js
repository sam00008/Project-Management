import mongoose, { Schema } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from 'crypto';
import { type } from "os";

const userSchema = new Schema(
    {
        avatar :{
            type : {
                url : String,
                localPath: String,
            },
            default : {
                url : `https://placehold.co/100x100/png`,
                localPath : ""
            }
        },

        username : {
            type : String,
            required : true,
            unique : true,
            lowercase : true,
            trim : true,
            index : true,
        },
        
        email : {
            type : String,
            required : true,
            unique : true,
            lowercase : true,
            trim : true
        },

        fullName : {
            type : String,
        },

        password : {
            type : String,
            required : [true, "Password is required"]
        },

        isEmailVerified : {
            type : Boolean,
            default : false
        },

        refreshToken : {
            type : String
        },

        forgorPasswordToken : {
            type : String
        },

        forgotPasswordExpiry : {
            type : Date
        },
        
        EmailVerificationExpiry : {
            type : Date
        },

         EmailVerificationToken:{
            type : String
         },
    },{ timestamps : true}
);
 
 userSchema.pre("save",async function (next) {
    if(!this.isModified("password")) return next();
     this.password = await bcrypt.hash(this.password,10);
     next();
 });

 userSchema.methods.isPasswordCorrect = async function(password) {
    return await bcrypt.compare(password,this.password);
 };

 userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        { //Payload : as many as information you provide.Information is user deatils.
            _id : this._id,
            email : this.email,
            username : this.username,
        },
        // Secert
        process.env.ACCESS_TOKEN_SECRET,
        // Token expire time or how much token are valid
        { 
            expiresIn : process.env.ACCESS_TOKEN_EXPIRY
        }
    )
 };
 //Same as the generateAccessToken
 userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id : this._id,
            email : this.email,
            username : this.username,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn : process.env.REFRESH_TOKEN_EXPIRY
        }
    )
 };

 userSchema.methods.generateTemporaryToken = function(){
    const unHashedToken  = crypto.randomBytes(20).toString("hex");

    const hashedToken = crypto
    .createHash("sha256")
    .update(unHashedToken)
    .digest("hex");

    const tokenExpiry = Date.now() + (20*60*1000); //20 min

     return {unHashedToken, hashedToken, tokenExpiry};
 };

const User = mongoose.model("user",userSchema);
export {User};