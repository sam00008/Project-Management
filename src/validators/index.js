import { body } from "express-validator";

const userRegisterValidator = () => {
    return [
        body("email")
            .trim()
            .notEmpty()
            .withMessage("Email is required")
            .isEmail()
            .withMessage("Email is invalid"),

        body("username")
            .trim()
            .notEmpty()
            .withMessage("Username is required")
            .isLowercase()
            .withMessage("Username must be in lower Case")
            .isLength({ min: 3 })
            .withMessage("Username must be at least 3 characters long"),

        body("password")
            .trim()
            .notEmpty()
            .withMessage("Password is Required"),


    ]
};

const userLoginValidator = () => {
    return [
        body("emai")
            .optional()
            .isEmail()
            .withMessage("Email is inavlid"),

        body("password")
            .notEmpty()
            .withMessage("Password is required"),
    ];
};

export { userRegisterValidator, userLoginValidator };