import React, { useState } from 'react';
import { NavLink, useNavigate } from 'react-router';
import { useAuth } from '../AuthStore/useAuth';
import { toast } from 'react-hot-toast';

function Header() {
  const [isOpen, setIsOpen] = useState(false);
  const { currentUser, logout } = useAuth();
  const navigate = useNavigate();

  const toggleMenu = () => setIsOpen(!isOpen);

  const handleLogout = () => {
    logout();
    toast.success("Logged out successfully");
    navigate("");
    setIsOpen(false);
  };

  const linkStyles = ({ isActive }) =>
    `transition-all duration-300 px-4 py-2 rounded-lg ${
      isActive 
        ? "bg-white text-blue-600 shadow-sm" 
        : "text-white hover:bg-blue-300"
    }`;

  return (
    <nav className="bg-blue-500 shadow-lg sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-20">
          
          {/* LEFT: Logo Section */}
          <div className="flex-shrink-0 flex items-center gap-3">
            <img 
              width="50px" 
              className="rounded-full bg-white p-1" 
              src="https://img.freepik.com/free-vector/user-circles-set_78370-4704.jpg" 
              alt="logo" 
            />
            <span className="text-white font-black text-2xl tracking-tight hidden sm:block">
              BlogApp
            </span>
          </div>

          {/* MIDDLE: User specific Dashboard Title */}
          <div className="flex-1 flex justify-center">
            {currentUser && (
              <span className="text-white font-bold text-xl tracking-wide">
                {currentUser.firstName} {currentUser.lastName}'s Dashboard
              </span>
            )}
          </div>

          {/* RIGHT: Desktop Menu */}
          <div className="hidden md:flex items-center gap-4">
            {!currentUser ? (
              <ul className="flex items-center gap-4 font-bold text-lg">
                <li><NavLink className={linkStyles} to="/">Home</NavLink></li>
                <li><NavLink className={linkStyles} to="/register">Register</NavLink></li>
                <li><NavLink className={linkStyles} to="/login">Login</NavLink></li>
              </ul>
            ) : (
              <div className="flex items-center gap-4 border-l border-blue-400 pl-4">
                {/* 2-digit initials fallback if profile image is missing */}
                <img 
                  className="w-10 h-10 rounded-full border-2 border-white object-cover shadow-md"
                  src={currentUser.profileImageUrl || `https://ui-avatars.com/api/?name=${currentUser.firstName[0]}${currentUser.lastName[0]}&background=ffffff&color=2563eb&bold=true&length=2`}
                  alt="profile"
                />
                <button 
                  onClick={handleLogout}
                  className="px-4 py-2 bg-red-500 text-white text-sm font-bold rounded-lg hover:bg-red-600 transition-all shadow-sm active:scale-95"
                >
                  Logout
                </button>
              </div>
            )}
          </div>

          {/* Mobile Menu Button */}
          <div className="md:hidden flex items-center">
            <button 
              onClick={toggleMenu}
              className="text-white focus:outline-none p-2 rounded-md hover:bg-blue-400 transition-colors"
            >
              <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                {isOpen ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16m-7 6h7" />
                )}
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Dropdown Menu */}
      <div className={`md:hidden transition-all duration-300 ease-in-out overflow-hidden ${isOpen ? 'max-h-[500px] opacity-100' : 'max-h-0 opacity-0'}`}>
        <ul className="px-4 pt-2 pb-6 space-y-2 bg-blue-600 shadow-inner">
          {!currentUser ? (
            <>
              <li><NavLink onClick={() => setIsOpen(false)} className="block py-3 px-4 text-white font-bold rounded-lg hover:bg-blue-500" to="/">Home</NavLink></li>
              <li><NavLink onClick={() => setIsOpen(false)} className="block py-3 px-4 text-white font-bold rounded-lg hover:bg-blue-500" to="/register">Register</NavLink></li>
              <li><NavLink onClick={() => setIsOpen(false)} className="block py-3 px-4 text-white font-bold rounded-lg hover:bg-blue-500" to="/login">Login</NavLink></li>
            </>
          ) : (
            <div className="pt-4 border-t border-blue-400 mt-2">
              <div className="flex items-center gap-3 px-4 mb-4">
                <img 
                  className="w-12 h-12 rounded-full border-2 border-white"
                  src={currentUser.profileImageUrl || `https://ui-avatars.com/api/?name=${currentUser.firstName[0]}${currentUser.lastName[0]}&background=ffffff&color=2563eb&bold=true&length=2`}
                  alt="user"
                />
                <span className="text-white font-bold">{currentUser.username}'s Dashboard</span>
              </div>
              <li>
                <button 
                  onClick={handleLogout}
                  className="w-full text-left py-3 px-4 bg-red-500 text-white font-bold rounded-lg hover:bg-red-700"
                >
                  Logout
                </button>
              </li>
            </div>
          )}
        </ul>
      </div>
    </nav>
  );
}

export default Header;