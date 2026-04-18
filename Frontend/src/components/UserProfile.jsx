import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthStore/useAuth';
import { useNavigate } from 'react-router';
import { toast } from 'react-hot-toast';
import axios from 'axios';

function UserProfile() {
  const currentUser = useAuth((state) => state.currentUser);
  const navigate = useNavigate();
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(true);

  // 1. Redirect if user details are lost (Security Guard)
  useEffect(() => {
    if (!currentUser) {
      const storedUser = localStorage.getItem('user');
      if (!storedUser) {
        navigate("/login");
      }
    }
  }, [currentUser, navigate]);

  // UserProfile.jsx

const fetchArticles = async () => {
  // 1. Check if currentUser and _id exist before making the call
  const userId = currentUser?._id || currentUser?.userId || currentUser?.id;
  
  if (!currentUser || !userId) {
    console.log("Waiting for user ID... from user profile reload");
    return;
  }

  try {
    setLoading(true);

    const res = await axios.get('https://capstone-project-rbl1.onrender.com/user-api/articles', { 
      withCredentials: true 
    });
    
    if (res.data && res.data.payload) {
      setArticles(res.data.payload);
    }
  } catch (err) {
    console.error("Fetch error:", err);
    toast.error("Failed to load your articles");
  } finally {
    setLoading(false);
  }
};

// 3. Ensure the useEffect triggers when currentUser changes
useEffect(() => {
  if (currentUser) {
    fetchArticles();
  }
}, [currentUser]); // This dependency is key!
  const handleReadMore = (article) => {
    // Navigate to detailed view
    navigate(`/article/${article._id}`, { state: { article } });
  };

  if (!currentUser) return null;

  return (
    <div className="min-h-screen bg-gray-50 pb-20">
      {/* Global Header handles the top nav; this is the page content */}
      <div className='max-w-7xl mx-auto p-6 lg:p-10'>
        
        <header className="mb-12">
          <h2 className='font-black text-4xl text-gray-900 tracking-tight'>
            Explore <span className="text-blue-600">Stories</span>
          </h2>
          <p className="text-gray-500 text-lg mt-2">
            Welcome back, {currentUser?.firstName}! Here is what's happening in the community.
          </p>
        </header>
        
        {loading ? (
          <div className="flex flex-col justify-center items-center mt-20 gap-4">
            <div className="animate-spin h-12 w-12 border-4 border-blue-500 border-t-transparent rounded-full"></div>
            <p className="text-gray-400 font-medium animate-pulse">Loading latest posts...</p>
          </div>
        ) : (
          <>
            {articles.length === 0 ? (
              <div className="text-center py-20 bg-white rounded-3xl border-2 border-dashed border-gray-200">
                <p className="text-gray-400 text-xl">No articles found in the feed.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                {articles.map((article) => (
                  <article 
                    key={article._id} 
                    className="bg-white rounded-3xl shadow-sm border border-gray-100 flex flex-col hover:shadow-xl hover:-translate-y-1 transition-all duration-300 overflow-hidden group"
                  >
                    <div className="p-8 flex-grow">
                      <div className="flex justify-between items-start mb-4">
                        <span className="text-[10px] font-bold text-blue-600 uppercase tracking-[0.2em] bg-blue-50 px-3 py-1 rounded-full">
                          {article.category || "General"}
                        </span>
                      </div>
                      
                      <h3 className="font-bold text-2xl mb-3 text-gray-900 group-hover:text-blue-600 transition-colors line-clamp-2">
                        {article.title}
                      </h3>
                      
                      <p className="text-gray-500 text-sm line-clamp-3 leading-relaxed mb-6">
                        {article.content}
                      </p>
                    </div>
                    
                    <div className="px-8 py-5 bg-gray-50/50 border-t border-gray-100 flex justify-between items-center">
                      <div className="flex items-center gap-3">
                        <img 
                          src={article.author?.profileImageUrl || `https://ui-avatars.com/api/?name=${article.author?.firstName || 'Author'}&background=2563eb&color=fff&bold=true`} 
                          className="w-8 h-8 rounded-full object-cover ring-2 ring-white shadow-sm" 
                          alt="author" 
                        />
                        <div className="flex flex-col">
                          <span className="text-xs font-bold text-gray-900">
                            {article.author?.firstName} {article.author?.lastName || "Unknown Author"}
                          </span>
                        </div>
                      </div>
                      
                      <button 
                        onClick={() => handleReadMore(article)} 
                        className="text-blue-600 text-xs font-bold hover:text-blue-800 flex items-center gap-1 group/btn"
                      >
                        Read Story 
                        <span className="group-hover/btn:translate-x-1 transition-transform">→</span>
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default UserProfile;