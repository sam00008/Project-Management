import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-Error.js";

const validate = (req, res, next) => {
  const errors = validationResult(req);

  // ✅ If no errors, proceed to next middleware/controller
  if (errors.isEmpty()) {
    return next();
  }

  // ✅ Extract errors in a clean format
  const extractedErrors = errors.array().map(err => ({
    [err.path]: err.msg,
  }));

  // ✅ Throw a custom API error
  throw new ApiError(422, "Received data is not valid", extractedErrors);
};

export { validate };
