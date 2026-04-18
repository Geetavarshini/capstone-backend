import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthStore/useAuth';
import axios from 'axios';
import { useNavigate } from 'react-router';
import { toast } from 'react-hot-toast';

function AuthorProfile() {
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(true);
  
  // Get both the user and the sync status from your store
  const currentUser = useAuth((state) => state.currentUser);
  const isAuthenticated = useAuth((state) => state.isAuthenticated);
  const navigate = useNavigate();
  useEffect(() => {
  const userId = currentUser?._id || currentUser?.userId || currentUser?.id;
  console.log("userId:", userId);
  console.log("isAuthenticated:", isAuthenticated);
  console.log("loading:", loading);
  // 1. If userId is null, we are still waiting for Zustand to hydrate from LocalStorage
  if (!userId) {
    console.log("Waiting for user data to hydrate...");
    return;
  }

  // 2. Define the fetch function inside to use the available userId
  const getArticles = async () => {
    try {
      setLoading(true);
      console.log("User ID ready, fetching articles for:", userId);
      const res = await axios.get(
        `https://capstone-project-rbl1.onrender.com/author-api/articles/${userId}`,
        { withCredentials: true }
      );

      if (res.data && res.data.payload) {
        setArticles(res.data.payload);
      }
    } catch (err) {
      if (err.response?.status !== 400) {
        toast.error("Failed to fetch articles");
      }
    } finally {
      setLoading(false);
    }
  };

  getArticles();
}, [currentUser]);

  return (
    <div className="p-8 max-w-7xl mx-auto min-h-screen bg-gray-50">
      <div className="flex flex-col md:flex-row justify-between items-center mb-10 gap-4">
        <div>
          <h1 className="text-4xl font-black text-gray-900 tracking-tight">My Workspace</h1>
          <p className="text-gray-500 font-medium italic">
            Welcome, {currentUser?.firstName} {currentUser?.lastName}
          </p>
        </div>
        <button 
          onClick={() => navigate('/add-article')}
          className="bg-blue-600 text-white px-8 py-3 rounded-full font-bold hover:bg-blue-700 transition-all shadow-lg hover:scale-105"
        >
          + New Article
        </button>
      </div>

      {articles.length === 0 && !loading ? (
        <div className="text-center py-24 bg-white rounded-3xl border-2 border-dashed border-gray-200">
          <p className="text-gray-400 text-xl font-medium">Your portfolio is empty.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {articles.map((article) => (
            <div 
              key={article._id} 
              className={`bg-white p-7 rounded-3xl shadow-sm border border-gray-100 flex flex-col justify-between transition-all group ${
                article.isArticleActive === false ? "opacity-60 bg-gray-50 grayscale-[0.3]" : "hover:shadow-xl"
              }`}
            >
              <div>
                <div className="flex justify-between">
                  <span className="px-3 py-1 bg-blue-50 text-blue-700 text-[10px] font-black rounded-full uppercase tracking-widest">
                    {article.category}
                  </span>
                  {article.isArticleActive === false && (
                    <span className="text-[10px] bg-red-100 text-red-600 px-2 py-1 rounded font-black uppercase tracking-tighter">
                      In Trash
                    </span>
                  )}
                </div>
                <h3 className="text-2xl font-bold text-gray-800 mt-5 mb-3 group-hover:text-blue-600 transition-colors leading-tight">
                  {article.title}
                </h3>
                <p className="text-gray-500 text-sm line-clamp-3 mb-8 leading-relaxed">
                  {article.content}
                </p>
              </div>
              
              <div className="flex items-center justify-between pt-5 border-t border-gray-50">
                 <div className="flex items-center gap-3">
                    <img 
                      src={currentUser?.profileImageUrl || `https://ui-avatars.com/api/?name=${currentUser?.firstName}`} 
                      className="w-10 h-10 rounded-full border-2 border-white shadow-sm object-cover" 
                      alt="avatar" 
                    />
                    <span className="text-[10px] font-black text-gray-400 uppercase tracking-tighter">
                      {article.isArticleActive === false ? "Hidden" : "Live"}
                    </span>
                 </div>
                 <button 
                   onClick={() => navigate(`/article/${article._id}`, { state: { article } })}
                   className={`${article.isArticleActive === false ? 'bg-red-500' : 'bg-gray-900'} text-white px-4 py-2 rounded-xl text-xs font-bold hover:bg-blue-600 transition-colors`}
                 >
                   {article.isArticleActive === false ? "View & Restore" : "View Full"}
                 </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default AuthorProfile;