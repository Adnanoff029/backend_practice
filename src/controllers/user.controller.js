import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async (userId) => {
   try {
      const user = await User.findById(userId);
      const accessToken = await user.generateAccessToken();
      const refreshToken = await user.generateRefreshToken();
      user.refreshToken = refreshToken;
      await user.save({ validateBeforeSave: false });
      return { accessToken, refreshToken };
   } catch (error) {
      throw new ApiError(
         500,
         "Something went wrong while generating referesh and access token",
      );
   }
};

const registerUser = asyncHandler(async (req, res) => {
   //Get user data from frontend.
   //Check for validation
   //Check if user already exists(through username, email)
   //Check if the files exist(avatar, coverImage)
   //Upload the files(image, avatar) to cloudinary
   //Create user object - create entry in DB
   //remove password and refreshToken from response
   //Check for user creation - Yes(true), NO(NULL)
   //Retun response

   const { userName, fullName, email, password } = req.body;
   // console.log(req.body);
   if (
      [fullName, email, userName, password].some(
         (field) => field?.trim() === "",
      )
   ) {
      throw new ApiError(400, "All fields are required");
   }

   const existingUser = await User.findOne({
      $or: [{ userName }, { email }],
   });

   if (existingUser) {
      throw new ApiError(409, "Username or email already exists");
   }

   const avatarLocalPath = req.files?.avatar[0]?.path;
   let coverImageLocalPath;
   if (
      req.files &&
      Array.isArray(req.files.coverImage) &&
      req.files.coverImage.length > 0
   ) {
      coverImageLocalPath = req.files?.coverImage[0]?.path;
   }

   if (!avatarLocalPath) {
      throw new ApiError(400, "Avatar file is required");
   }

   const avatar = await uploadOnCloudinary(avatarLocalPath);
   const coverImage = await uploadOnCloudinary(coverImageLocalPath);

   if (!avatar) {
      throw new ApiError(400, "Avatar file not uploaded");
   }

   const user = await User.create({
      fullName,
      avatar: avatar.url,
      coverImage: coverImage ? coverImage.url : "",
      email,
      password,
      userName: userName.toLowerCase(),
   });

   const createdUser = await User.findById(user._id).select(
      "-password -refreshToken",
   );

   if (!createdUser) {
      throw new ApiError(
         500,
         "Something went wrong while registering the user",
      );
   }

   return res
      .status(201)
      .json(new ApiResponse(200, createdUser, "User registered successfully"));
});

// const loginUser = asyncHandler(async (req, res) => {
//   // Get userName/email and password from frontend.
//   // Validate the userName/email from database.
//   // if userName is present the continue.
//   // Check for password.
//   // if password is correct then:
//   // generate access token and refresh token
//   // Send secure cookies.
//   // else throw error regarding incorrect userName or password.
//   const { email, userName, password } = req.body;
//   // console.log(email);

//   if (!userName && !email) {
//     throw new ApiError(400, "username or email is required");
//   }

//   const user = await User.findOne({
//     $or: [{ userName }, { email }],
//   });

//   if (!user) {
//     throw new ApiError(400, "User not found");
//   }

//   const isPasswordValid = await user.isPasswordCorrect(password);

//   if (!isPasswordValid) throw new ApiError(400, "Invalid user's credentials");

//   const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
//     user._id,
//   );

//   const loggedInUser = await User.findById(user._id).select(
//     "-password, -refreshToken",
//   );

//   const options = {
//     httpOnly: true,
//     secure: true,
//   };
//   // console.log(accessToken);
//   // console.log(typeof accessToken, accessToken );
//   return res
//     .status(200)
//     .cookie("accessToken", accessToken, options)
//     .cookie("refreshToken", refreshToken, options)
//     .json(
//       new ApiResponse(
//         200,
//         {
//           user: loggedInUser,
//           accessToken,
//           refreshToken,
//         },
//         "User Logged in successfully",
//       ),
//     );
// });

const loginUser = asyncHandler(async (req, res) => {
   // req body -> data
   // username or email
   //find the user
   //password check
   //access and referesh token
   //send cookie

   const { email, userName, password } = req.body;
   // console.log(email);

   if (!userName && !email) {
      throw new ApiError(400, "username or email is required");
   }

   // Here is an alternative of above code based on logic discussed in video:
   // if (!(username || email)) {
   //     throw new ApiError(400, "username or email is required")

   // }

   const user = await User.findOne({
      $or: [{ userName }, { email }],
   });

   if (!user) {
      throw new ApiError(404, "User does not exist");
   }

   const isPasswordValid = await user.isPasswordCorrect(password);

   if (!isPasswordValid) {
      throw new ApiError(401, "Invalid user credentials");
   }

   const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
      user._id,
   );

   const loggedInUser = await User.findById(user._id).select(
      "-password -refreshToken",
   );
   const options = {
      httpOnly: true,
      secure: true,
   };
   return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
         new ApiResponse(
            200,
            {
               user: loggedInUser,
               accessToken,
               refreshToken,
            },
            "User logged In Successfully",
         ),
      );
});

const logoutUser = asyncHandler(async (req, res) => {
   await User.findByIdAndUpdate(
      req.user._id,
      {
         $set: {
            refreshToken: undefined,
         },
      },
      {
         new: true,
      },
   );

   const options = {
      httpOnly: true,
      secure: true,
   };

   return res
      .status(200)
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options)
      .json(new ApiResponse(200, {}, "User logged out successfully"));
});

const refreshAccessToken = asyncHandler(async (req, res, next) => {
   const incomingRefreshToken =
      req.cookies.refreshToken || req.body.refreshToken;
   if (!incomingRefreshToken) {
      throw new ApiError(401, "Unauthorized request");
   }
   try {
      const decodedToken = jwt.verify(
         incomingRefreshToken,
         process.env.REFRESH_TOKEN_SECRET,
      );

      const user = await User.findById(decodedToken?._id);

      if (!user) {
         throw new ApiError(401, "Invalid refresh token");
      }

      if (incomingRefreshToken != user?.refreshToken) {
         throw new ApiError(401, "Refesh token is expired");
      }

      const options = {
         httpOnly: true,
         secure: true,
      };

      const { newAccessToken, newRefreshToken } =
         await generateAccessAndRefreshTokens(user._id);

      return res
         .status(200)
         .cookie("accessToken", newAccessToken, options)
         .cookie("refreshToken", newRefreshToken, options)
         .json(
            new ApiResponse(
               200,
               { accessToken: newAccessToken, refreshToken: newRefreshToken },
               "Access Token refreshed successfully.",
            ),
         );
   } catch (error) {
      throw new ApiError(401, Error?.message("Invalid refresh token."));
   }
});

const getCurrentUser = asyncHandler(async (req, res, next) => {
   return res
      .status(200)
      .json(200, req.user, "Current user fetched successfully.");
});

const changeCurrentPassword = asyncHandler(async (req, res, next) => {
   const { oldPassword, newPassword } = req.body;
   console.log(req.user);
   const user = await User.findById(req.user?._id);
   const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
   if (!isPasswordCorrect) {
      throw new ApiError(400, "Invalid password");
   }
   user.password = newPassword;
   await user.save({ validateBeforeSave: false });

   return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password updated successfully"));
});

const updateAccountDetails = asyncHandler(async (req, res, next) => {
   const { fullName, email } = req.body;
   if (!fullName || !email) {
      throw new ApiError(400, "All fields are required.");
   }
   const user = User.findByIdAndUpdate(
      req.user?._id,
      {
         $set: { email: email, fullName: fullName },
      },
      { new: true },
   ).select("-password");

   return res
      .status(200)
      .json(new ApiResponse(200, user, "Account updated successfully"));
});

const updateUserAvatar = asyncHandler(async (req, res, next) => {
   const newAvatar = req.file?.avatar.path;
   if (!newAvatar) {
      throw new ApiError(400, "Avatar file is missing.");
   }

   const avatar = await User.uploadOnCloudinary(newAvatar);

   if (!avatar.url) {
      throw new ApiError(500, "Error while uploading the avatar file.");
   }
   const user = User.findByIdAndUpdate(
      req.user?._id,
      {
         $set: { avatar: avatar.url },
      },
      {
         new: true,
      },
   ).select("-password");

   return res
      .status(200)
      .json(new ApiResponse(200, user, "User avatar updated successfully"));
});

const updateUserCoverImage = asyncHandler(async (req, res, next) => {
   const newCoverImage = req.file?.avatar.path;
   if (!newCoverImage) {
      throw new ApiError(400, "Cover image file is missing.");
   }

   const coverImage = await User.uploadOnCloudinary(newCoverImage);

   if (!coverImage.url) {
      throw new ApiError(500, "Error while uploading the avatar file.");
   }
   const user = User.findByIdAndUpdate(
      req.user?._id,
      {
         $set: { coverImgae: coverImage.url },
      },
      {
         new: true,
      },
   ).select("-password");

   return res
      .status(200)
      .json(new ApiResponse(200, user, "Cover image updated successfully"));
});

export {
   registerUser,
   loginUser,
   logoutUser,
   refreshAccessToken,
   changeCurrentPassword,
   getCurrentUser,
   updateAccountDetails,
   updateUserAvatar,
   updateUserCoverImage,
};
