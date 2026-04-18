import exp from 'express';
import {register,authenticate} from '../services/authService.js'
import { verifyToken } from '../middlewares/verifyToken.js';
import { checkUser } from '../middlewares/checkUser.js';
import { ArticleModel } from '../models/articleModel.js';
import { upload } from '../config/multer.js';
import { uploadToCloudinary } from '../config/cloudinaryUpload.js'; 
import cloudinary from '../config/cloudinary.js';
export const userRoute=exp.Router();


//register user
userRoute.post(
        "/users",
        upload.single("profileImageUrl"), // multer middleware to handle file upload
        async (req, res, next) => {
        let cloudinaryResult;

            try {
                let userObj = req.body;

                //  Step 1: upload image to cloudinary from memoryStorage (if exists)
                if (req.file) {
                cloudinaryResult = await uploadToCloudinary(req.file.buffer);
                }

                // Step 2: call existing register()
                const newUserObj = await register({
                ...userObj,
                role: "USER",
                profileImageUrl: cloudinaryResult?.secure_url,
                });

                res.status(201).json({
                message: "user created",
                payload: newUserObj,
                });

            } catch (err) {

                // Step 3: rollback 
                if (cloudinaryResult?.public_id) {
                await cloudinary.uploader.destroy(cloudinaryResult.public_id);
                }

                next(err); // send to your error middleware
            }

        }
        );

// read all articles(protected route)
userRoute.get('/articles', verifyToken("USER"), checkUser, async (req, res) => {
    let allArticles = await ArticleModel.find({ isArticleActive: true })
        .populate("author", "firstName lastName profileImageUrl") 
        .populate("comments.user", "firstName lastName profileImageUrl");

    if (!allArticles || allArticles.length === 0) {
        return res.status(200).json({ message: "No Articles Found", payload: [] });
    }
    
    res.status(200).json({ message: "All articles", payload: allArticles });
});

// userRoute.js

// userRoute.js

userRoute.post("/articles", verifyToken("USER"), checkUser, async (req, res) => {
    
    const userIdFromToken = req.user.userId || req.user._id; 
    
    const { articleId, comment } = req.body; 

    try {
        const articleWithComment = await ArticleModel.findOneAndUpdate(
            { _id: articleId, isArticleActive: true },
            { $push: { comments: { user: userIdFromToken, comment } } },
            { new: true, runValidators: true }
        )
        .populate("author", "firstName lastName profileImageUrl")
        .populate("comments.user", "firstName lastName profileImageUrl");

        if (!articleWithComment) {
            return res.status(404).json({ message: "Article not found" });
        }

        res.json({ message: "Comment added successfully", payload: articleWithComment });
    } catch (err) {
        res.status(500).json({ message: "Internal Server Error", error: err.message });
    }
});