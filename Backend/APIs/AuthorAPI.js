import mongoose from 'mongoose';
// --- authorRoute.js ---
import exp from 'express';
import { ArticleModel } from '../models/articleModel.js';
import { checkAuthor } from '../middlewares/checkAuthor.js';
import { verifyToken } from '../middlewares/verifyToken.js';
import { register } from '../services/authService.js';
import { upload } from '../config/multer.js';
import { uploadToCloudinary } from '../config/cloudinaryUpload.js'; 
import cloudinary from '../config/cloudinary.js';
export const authorRoute = exp.Router();

authorRoute.post(
  "/users",
  upload.single("profileImageUrl"),
  async (req, res, next) => {
    let cloudinaryResult;
    try {
      let userObj = req.body;

      // Step 1: upload image to cloudinary if exists
      if (req.file) {
        cloudinaryResult = await uploadToCloudinary(req.file.buffer);
      }

      // Step 2: call register() with AUTHOR role
      const newAuthorObj = await register({
        ...userObj,
        role: "AUTHOR",
        profileImageUrl: cloudinaryResult?.secure_url,
      });

      res.status(201).json({
        message: "Author created",
        payload: newAuthorObj,
      });

    } catch (err) {
      // Step 3: rollback cloudinary if DB save fails
      if (cloudinaryResult?.public_id) {
        await cloudinary.uploader.destroy(cloudinaryResult.public_id);
      }
      next(err);
    }
  }
);

// 1. Create Article (Fixed to use Token for ID)
authorRoute.post('/articles', verifyToken("AUTHOR"), checkAuthor, async (req, res) => {
    try {
        // Extract author ID directly from the verified token
        const authorIdFromToken = req.user.userId; 
        const { title, category, content } = req.body;

        const newArticle = new ArticleModel({
            title,
            category,
            content,
            author: authorIdFromToken, 
            isArticleActive: true
        });

        const createdArticleDoc = await newArticle.save();
        res.status(201).json({ message: "Article Created", payload: createdArticleDoc });
    } catch (err) {
        res.status(500).json({ message: "Failed to create article", error: err.message });
    }
});

// authorRoute.js



authorRoute.get('/articles/:authorId', verifyToken("AUTHOR"), checkAuthor, async (req, res) => {
    try {
        const { authorId } = req.params;

        // 1. Validation: Stop 'undefined' or invalid IDs from hitting the DB
        if (!authorId || authorId === 'undefined' || !mongoose.Types.ObjectId.isValid(authorId)) {
            console.log("❌ Invalid Author ID received:", authorId);
            return res.status(400).json({ message: "Invalid Author ID" });
        }

        // 2. Fetch: Use the Author ID to find matching articles
        // Ensure the field name 'author' matches your Article Schema
        const allArticles = await ArticleModel.find({ 
            author: authorId
        }).populate("author", "firstName lastName profileImageUrl");

        // 3. Debugging: Check your Terminal/Console!
        console.log(`✅ Found ${allArticles.length} articles for Author ID: ${authorId}`);

        res.status(200).json({ 
            message: "Articles fetched successfully", 
            payload: allArticles 
        });
    } catch (err) {
        console.error("❌ Backend Error:", err);
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// 3. Edit Article
authorRoute.put('/articles', verifyToken("AUTHOR"), checkAuthor, async (req, res) => {
    try {
        const { articleId, title, category, content } = req.body;
        const authorId = req.user.userId; // Securely get author from token

        // Ensure the article belongs to this author before updating
        let updatedArticle = await ArticleModel.findOneAndUpdate(
            { _id: articleId, author: authorId },
            { $set: { title, category, content } },
            { new: true }
        );

        if (!updatedArticle) {
            return res.status(404).json({ message: "Article not found or unauthorized" });
        }

        res.status(200).json({ message: "Article Updated", payload: updatedArticle });
    } catch (err) {
        res.status(500).json({ message: "Update failed", error: err.message });
    }
});

// 4. Soft Delete Article
authorRoute.patch("/articles/:id/status", verifyToken("AUTHOR"), async (req, res) => {
    const { id } = req.params;
    const { isArticleActive } = req.body;

    const article = await ArticleModel.findOneAndUpdate(
        { _id: id, author: req.user.userId }, // Security: Must be owner
        { isArticleActive },
        { new: true }
    );

    if (!article) return res.status(404).json({ message: "Article not found" });
    
    res.status(200).json({ 
        message: `Article ${isArticleActive ? "restored" : "deleted"}`, 
        article 
    });
});