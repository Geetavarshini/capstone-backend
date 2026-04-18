import React from 'react';
import { useNavigate } from 'react-router';
import { useAuth } from '../AuthStore/useAuth';

function Home() {
  const navigate = useNavigate();
  const isAuthenticated = useAuth((state) => state.isAuthenticated);
  const currentUser = useAuth((state) => state.currentUser);

  const handleStartWriting = () => {
    if (isAuthenticated) {
      navigate(currentUser.role === "AUTHOR" ? "/author-profile" : "/user-profile");
    } else {
      navigate("/register");
    }
  };

  return (
    <div className="bg-white min-h-screen">

      {/* HERO */}
      <section className="pt-20 pb-16 lg:pt-32 lg:pb-24">
        <div className="max-w-7xl mx-auto px-6 lg:px-10">
          <div className="max-w-3xl">
            <span className="inline-block text-sm font-semibold text-blue-600 bg-blue-50 px-4 py-1 rounded-full mb-6">
              A space for real voices
            </span>
            <h1 className="text-6xl lg:text-8xl font-black text-gray-900 leading-[0.9] tracking-tighter mb-8">
              Write. Read. <br />
              <span className="text-blue-600">Connect.</span>
            </h1>
            <p className="text-xl text-gray-500 leading-relaxed mb-10 max-w-xl">
              Share your stories, ideas, and insights with readers who care about depth and quality.
            </p>

            <div className="flex flex-col sm:flex-row gap-4">
              <button
                onClick={handleStartWriting}
                className="px-8 py-4 bg-gray-900 text-white font-bold rounded-2xl hover:bg-blue-600 transition-all active:scale-95"
              >
                {isAuthenticated ? "Go to Dashboard" : "Get Started — It's Free"}
              </button>
              {!isAuthenticated && (
                <button
                  onClick={() => navigate("/login")}
                  className="px-8 py-4 bg-white text-gray-900 font-bold rounded-2xl border-2 border-gray-100 hover:border-gray-200 hover:bg-gray-50 transition-all active:scale-95"
                >
                  Sign In
                </button>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* FEATURES */}
      <section className="bg-gray-50 py-24">
        <div className="max-w-7xl mx-auto px-6 lg:px-10">
          <h2 className="text-3xl font-black text-gray-900 tracking-tight mb-2">
            Built for creators and readers
          </h2>
          <p className="text-gray-500 mb-12">Everything you need to write, publish, and discover great content.</p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="bg-white p-10 rounded-3xl border border-gray-100">
              <div className="w-12 h-12 bg-blue-50 text-blue-600 rounded-xl flex items-center justify-center mb-6">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
              </div>
              <h3 className="font-bold text-xl mb-3">Author Dashboard</h3>
              <p className="text-gray-500 text-sm leading-relaxed">
                A clean, distraction-free space to write and manage all your articles in one place.
              </p>
            </div>

            <div className="bg-white p-10 rounded-3xl border border-gray-100">
              <div className="w-12 h-12 bg-purple-50 text-purple-600 rounded-xl flex items-center justify-center mb-6">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h3 className="font-bold text-xl mb-3">Secure by Design</h3>
              <p className="text-gray-500 text-sm leading-relaxed">
                Role-based access control and HTTP-only cookies keep your account and content protected.
              </p>
            </div>

            <div className="bg-white p-10 rounded-3xl border border-gray-100">
              <div className="w-12 h-12 bg-green-50 text-green-600 rounded-xl flex items-center justify-center mb-6">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 8h2a2 2 0 012 2v6a2 2 0 01-2 2h-2v4l-4-4H9a1.994 1.994 0 01-1.414-.586m0 0L11 14h4a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2v4l.586-.586z" />
                </svg>
              </div>
              <h3 className="font-bold text-xl mb-3">Reader Community</h3>
              <p className="text-gray-500 text-sm leading-relaxed">
                Read articles across categories and leave comments to engage directly with authors.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section className="py-24">
        <div className="max-w-7xl mx-auto px-6 lg:px-10">
          <h2 className="text-3xl font-black text-gray-900 tracking-tight mb-2">How it works</h2>
          <p className="text-gray-500 mb-12">Get started in three simple steps.</p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              { step: "01", title: "Create an account", desc: "Sign up as a Reader to explore content or as an Author to start publishing." },
              { step: "02", title: "Explore or write", desc: "Readers browse articles by category. Authors get a personal dashboard to create and manage posts." },
              { step: "03", title: "Engage", desc: "Comment on articles, connect with authors, and be part of a growing community of thinkers." }
            ].map(({ step, title, desc }) => (
              <div key={step} className="flex gap-6">
                <span className="text-4xl font-black text-gray-100">{step}</span>
                <div>
                  <h3 className="font-bold text-lg mb-2 text-gray-900">{title}</h3>
                  <p className="text-gray-500 text-sm leading-relaxed">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

     
  <section className="py-24 bg-gray-50">
    <div className="max-w-5xl mx-auto px-6 text-center">
      <h2 className="text-4xl font-black text-gray-900 mb-4">Ready to share your story?</h2>
      
      {isAuthenticated ? (
        // ✅ Show this when logged in
        <div>
          <p className="text-gray-500 mb-8 text-lg">Welcome back, {currentUser?.firstName}!</p>
          <button
            onClick={handleStartWriting}
            className="bg-blue-600 text-white px-10 py-4 rounded-2xl font-bold hover:bg-blue-700 transition-all active:scale-95"
          >
            Go to Dashboard
          </button>
        </div>
      ) : (
        // ✅ Show this when not logged in
        <div>
          <p className="text-gray-500 mb-8 text-lg">Join as an author or reader — no experience needed.</p>
          <div className="flex justify-center gap-4 flex-wrap">
            <button
              onClick={() => navigate("/register")}
              className="bg-blue-600 text-white px-10 py-4 rounded-2xl font-bold hover:bg-blue-700 transition-all active:scale-95"
            >
              Create an Account
            </button>
            <button
              onClick={() => navigate("/login")}
              className="bg-white text-gray-900 px-10 py-4 rounded-2xl font-bold border-2 border-gray-100 hover:bg-gray-50 transition-all active:scale-95"
            >
              Sign In
            </button>
          </div>
        </div>
      )}
    </div>
  </section>

    </div>
  );
}

export default Home;