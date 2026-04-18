import React from 'react';
import { Outlet } from 'react-router';
import Footer from './Footer';
import Header from './Header';
import { useAuth } from '../AuthStore/useAuth';

function RootLayout() {
  const { loading, isAuthenticated } = useAuth();

  if (loading && !isAuthenticated) {
    return (
      <div className="min-h-screen flex flex-col justify-center items-center bg-blue-500">
        <div className="animate-spin h-12 w-12 border-4 border-white border-t-transparent rounded-full mb-4"></div>
        <h2 className="text-white font-bold text-xl animate-pulse">
          Verifying Session...
        </h2>
      </div>
    );
  }

  return (
    <div className="flex flex-col min-h-screen">
      <Header />
      <main className="flex-grow bg-gray-50">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}

export default RootLayout;