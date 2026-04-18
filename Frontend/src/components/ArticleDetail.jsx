import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { useAuth } from '../AuthStore/useAuth';
import { toast } from 'react-hot-toast';
import axios from 'axios';
import EditArticle from './EditArticle';

function ArticleDetail() {
  const { state } = useLocation();
  const navigate = useNavigate();
  const currentUser = useAuth((state) => state.currentUser);

  const [article, setArticle] = useState(state?.article || null);
  const [isEditing, setIsEditing] = useState(false);
  const [commentText, setCommentText] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Sync if navigation state changes
  useEffect(() => {
    if (state?.article) {
      setArticle(state.article);
    }
  }, [state]);

  // Check if current user is the author
  const isAuthor =
    currentUser?._id === article?.author?._id ||
    currentUser?.id === article?.author?._id;

  // --- SOFT DELETE / RESTORE LOGIC ---
  const handleToggleStatus = async (newStatus) => {
    const action = newStatus ? "restore" : "delete";
    if (!window.confirm(`Are you sure you want to ${action} this article?`)) return;
    
    try {
      const res = await axios.patch(
        `https://capstone-project-rbl1.onrender.com/author-api/articles/${article._id}/status`,
        { isArticleActive: newStatus },
        { withCredentials: true }
      );
      
      // Update local state so UI updates without navigating away
      setArticle(prev => ({ ...prev, isArticleActive: newStatus }));
      toast.success(`Article ${newStatus ? "restored" : "moved to trash"}`);
      
      // We don't navigate away, so the author can see the "Restore" button immediately
    } catch (err) {
      toast.error("Failed to update status");
    }
  };

  // --- POST COMMENT ---
  const handlePostComment = async (e) => {
    e.preventDefault();
    if (!commentText.trim()) return;
    setIsSubmitting(true);
    try {
      const commentBody = {
        user: currentUser._id,
        articleId: article._id,
        comment: commentText,
      };

      const res = await axios.post(
        'https://capstone-project-rbl1.onrender.com/user-api/articles',
        commentBody,
        { withCredentials: true }
      );
      setArticle(res.data.payload);
      setCommentText("");
      toast.success("Comment posted");
    } catch (err) {
      toast.error("Failed to post comment");
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!article) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen text-gray-400">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mb-4"></div>
        <p className="font-medium">Loading article...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white pb-32">
      <div className="max-w-2xl mx-auto px-4 py-8">

        {/* HEADER NAVIGATION */}
        <div className="flex justify-between items-center mb-10">
          <button
            onClick={() => (isEditing ? setIsEditing(false) : navigate(-1))}
            className="p-2 -ml-2 hover:bg-gray-100 rounded-full transition-all text-gray-600"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7" />
            </svg>
          </button>

          {isAuthor && !isEditing && (
            <div className="flex gap-3">
              {article.isArticleActive !== false ? (
                <>
                  <button
                    onClick={() => setIsEditing(true)}
                    className="px-4 py-1.5 border border-gray-200 rounded-full text-sm font-semibold hover:bg-gray-50 transition-colors"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleToggleStatus(false)}
                    className="px-4 py-1.5 bg-red-50 text-red-600 rounded-full text-sm font-semibold hover:bg-red-100 transition-colors"
                  >
                    Delete
                  </button>
                </>
              ) : (
                <button
                  onClick={() => handleToggleStatus(true)}
                  className="px-6 py-1.5 bg-blue-600 text-white rounded-full text-sm font-bold shadow-md hover:bg-blue-700 transition-all"
                >
                  Restore Article
                </button>
              )}
            </div>
          )}
        </div>

        {isEditing ? (
          <EditArticle
            article={article}
            setArticle={setArticle}
            setIsEditing={setIsEditing}
          />
        ) : (
          /* VIEW MODE */
          <>
            {/* TRASH STATUS BANNER */}
            {isAuthor && article.isArticleActive === false && (
              <div className="mb-8 bg-red-50 border border-red-100 text-red-700 p-4 rounded-2xl text-center animate-pulse">
                <p className="text-xs font-black uppercase tracking-widest">Article is in Trash</p>
                <p className="text-[10px] mt-1">Hidden from public view. Click 'Restore' to publish again.</p>
              </div>
            )}

            <article className="mb-12">
              <header className="mb-8">
                <span className="px-3 py-1 bg-blue-50 text-blue-600 text-[10px] font-bold uppercase tracking-widest rounded-md">
                  {article.category}
                </span>
                <h1 className="text-4xl font-black text-gray-900 mt-4 mb-6 leading-tight">
                  {article.title}
                </h1>
                <div className="flex items-center gap-3 border-b border-gray-100 pb-8">
                  <img
                    src={article.author?.profileImageUrl || `https://ui-avatars.com/api/?name=${article.author?.firstName}`}
                    className="w-12 h-12 rounded-full object-cover"
                    alt="author"
                  />
                  <div>
                    <p className="font-bold text-gray-900 leading-none">
                      {article.author?.firstName} {article.author?.lastName}
                    </p>
                    <p className="text-gray-400 text-xs mt-1">Author • {Math.ceil(article.content.length / 500)} min read</p>
                  </div>
                </div>
              </header>

              <section className="text-gray-800 text-lg leading-relaxed whitespace-pre-wrap">
                {article.content}
              </section>

              {/* TIMESTAMPS */}
              <div className="mt-12 pt-6 border-t border-gray-50 flex flex-col sm:flex-row sm:justify-between gap-4">
                <div className="flex flex-col">
                  <span className="text-[10px] font-black uppercase tracking-widest text-gray-400">
                    Published
                  </span>
                  <p className="text-sm text-gray-600 font-medium">
                    {new Date(article.createdAt).toLocaleDateString()} at{" "}
                    {new Date(article.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </p>
                </div>
                {article.updatedAt && article.updatedAt !== article.createdAt && (
                  <div className="flex flex-col sm:text-right">
                    <span className="text-[10px] font-black uppercase tracking-widest text-blue-400">
                      Last Modified
                    </span>
                    <p className="text-sm text-gray-500 italic">
                      {new Date(article.updatedAt).toLocaleDateString()}
                    </p>
                  </div>
                )}
              </div>
            </article>

            <hr className="border-gray-100 mb-10" />

            {/* COMMENTS SECTION */}
            <div className="mt-8 pb-20">
              <h2 className="font-black text-xl mb-8 tracking-tight">
                Comments <span className="text-gray-300 ml-1">{article.comments?.length || 0}</span>
              </h2>
              <div className="space-y-6">
                {article.comments?.length > 0 ? (
                  article.comments.map((c, idx) => (
                    <div key={idx} className="flex gap-4 items-start">
                      <img
                        src={c.user?.profileImageUrl || `https://ui-avatars.com/api/?name=${c.user?.firstName}`}
                        className="w-10 h-10 rounded-full object-cover"
                        alt="user"
                      />
                      <div className="flex-1 bg-gray-50 p-4 rounded-2xl rounded-tl-none">
                        <p className="font-bold text-sm text-gray-900 mb-1">
                          {c.user?.firstName} {c.user?.lastName}
                        </p>
                        <p className="text-gray-700 text-sm leading-normal">{c.comment}</p>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-center text-gray-400 py-10 italic">No comments yet.</p>
                )}
              </div>
            </div>

            {/* STICKY COMMENT BAR */}
            {!isAuthor && article.isArticleActive !== false && (
              <div className="fixed bottom-0 left-0 w-full bg-white/80 backdrop-blur-md border-t p-4 z-50">
                <div className="max-w-2xl mx-auto">
                  <form
                    onSubmit={handlePostComment}
                    className="flex items-center border bg-gray-50 rounded-2xl px-4 py-2.5"
                  >
                    <input
                      type="text"
                      placeholder="Add a comment..."
                      value={commentText}
                      onChange={(e) => setCommentText(e.target.value)}
                      className="w-full bg-transparent outline-none text-sm"
                    />
                    <button
                      type="submit"
                      disabled={!commentText.trim() || isSubmitting}
                      className="text-blue-600 font-bold text-sm ml-2 disabled:text-gray-300"
                    >
                      Post
                    </button>
                  </form>
                </div>
              </div>
            )}

            {/* AUTHOR MODE BANNER */}
            {isAuthor && (
              <div className="mt-10 bg-blue-50/50 rounded-2xl p-6 text-center border border-blue-100">
                <p className="text-xs font-bold text-blue-900 uppercase tracking-widest">Author Mode</p>
                <p className="text-blue-600/70 text-[10px] mt-1 italic">
                  Use the header buttons to manage this article's visibility.
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default ArticleDetail;