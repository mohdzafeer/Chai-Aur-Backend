import {asyncHandler} from '../utils/asyncHandler.js'
import {ApiErrors} from '../utils/ApiErrors.js'
import {ApiResponse} from '../utils/ApiResponse.js'
import { User} from '../models/user.model.js'
import { uploadOnCloudinary} from '../utils/cloudinary.js'


const generateAccessAndRefreshTokens=async(userId)=>{
    try {
        const user= await User.findById(userId)
        const accessToken= user.generateAccessToken()
        const refreshToken=user.generateRefreshToken()

        user.refreshToken=refreshToken
        await user.save({validateBeforeSave:false})

        return {accessToken,refreshToken}

    } catch (error) {
        throw new ApiErrors(500,"Something went wrong while generating Access and Refresh Tokens")
    }
}


const registerUser=asyncHandler(async (req,res)=>{
    // get user details from frontend
    // validation-not empty
    // check if user already exist : username and email
    // check for avatar
    // upload them to cloudinary,avatar
    // create user object-create entry in db
    // remove password and refresh token from res
    // check for user creation
    // return res
    
    const{fullName,email,username,password}=req.body
    console.log("email : ",email);

    if(
        [fullName,email,username,password].some((field)=>field?.trim()==="")
    ){
        throw new ApiErrors(400,"All fields are required")
    }

    const existedUser=await User.findOne({
        $or:[
            {username},
            {email}
        ]
    })

    if(existedUser){
        throw new ApiErrors(409,"username or email already exist")
    }

    // console.log(req.files);

    const avatarLocalPath=req.files?.avatar[0]?.path
    // const coverImageLocalPath=req.files?.coverImage[0]?.path

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length>0){
        coverImageLocalPath=req.files.coverImage[0].path
    }

    if(!avatarLocalPath){
        throw new ApiErrors(400,"Avatar file is required ")
    }

    const avatar=await uploadOnCloudinary(avatarLocalPath)
    const coverImage=await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiErrors(400,"Avatar file is required ")
    }
    
    const user= await User.create({
        fullName,
        avatar:avatar.url,
        coverImage:coverImage?.url || "",
        username:username.toLowerCase(),
        email,
        password
    })

    const createdUser=await User.findById(user._id).select(
        "-password -refreshToken"

    )

    if(!createdUser){
        throw new ApiErrors(500,"Failed to create user")
    }


    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered successfully")
    )
})


const loginUser=asyncHandler(async (req,res)=>{
    // req body -> data
    // username or email
    // find the user
    // password check
    // access and refresh token
    // send cookie

    const {email,username,password}=req.body

    if(!username && !email){
        throw new ApiErrors(400,"Username or email is required")
    }

    const user= await User.findOne({
        $or:[
            {username},
            {email}
        ]
    })

    if(!user){
        throw new ApiErrors(404,"User does not exist")
    }

    const isPasswordValid= await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiErrors(401,"Invalid User Credentials")
    }

    const {accessToken,refreshToken}= await generateAccessAndRefreshTokens(user._id)

    const loggedInUser=await User.findById(user._id).select("-password -refreshToken ")

    const options={
        httpOnly:true,
        secure:true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,
            {
                user:loggedInUser,accessToken,refreshToken
            },
            "User logged In successfully"
        )
    )

})

const logoutUser=asyncHandler(async (req,res)=>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                refreshToken:undefined
            }
            
        },
        {
            new:true
        }
    )
    const options={
        httpOnly:true,
        secure:true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"User Logged Out"))
})

export {registerUser,loginUser,logoutUser}