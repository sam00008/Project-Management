import { ApiResponse } from "../utils/api_Response.js";
import { ApiError } from "../utils/api-Error.js";
import { asyncHandler } from "../utils/async-handler.js";

const healthCheck = asyncHandler(async (req, res) => {
    res
      .status(200)
      .json(new ApiResponse(200, null, "Server health is awesome")); // ✅ Fix here
});

export { healthCheck };


// const healthCheck = (req, res) => {
//     try {
//         res.status(200).json(new ApiResponse(200, {
//             message: "Server health is awesome"
//         }));
//     } catch (error) {
//         res.status(500).json(new ApiError(500, "Kuch tho garbad hai", error));
//     }
// };
