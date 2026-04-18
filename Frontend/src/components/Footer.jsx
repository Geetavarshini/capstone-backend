import React from 'react';

function Footer() {
  const currentYear = new Date().getFullYear();

  // Social Link Component for reusability
  const SocialLink = ({ href, icon, text, isExternal = true }) => (
    <li>
      <a 
        href={href}
        target={isExternal ? "_blank" : "_self"}
        rel={isExternal ? "noreferrer" : ""}
        className="group flex items-center text-gray-600 hover:text-blue-600 transition-colors text-sm"
      >
        <span className="mr-3 text-gray-400 group-hover:text-blue-600 transition-colors">
          {icon}
        </span>
        {text}
        {isExternal && (
          <svg className="w-3 h-3 ml-1 opacity-0 group-hover:opacity-100 transition-all transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
        )}
      </a>
    </li>
  );

  return (
    <footer className="bg-gray-100 border-t border-gray-200 pt-20 pb-10 mt-auto">
      <div className="max-w-7xl mx-auto px-6 lg:px-10">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12 mb-16">
          
          {/* Brand Section */}
          <div className="lg:col-span-1">
            <h3 className="text-2xl font-black text-gray-900 tracking-tighter mb-4">
              Blog<span className="text-blue-600">App.</span>
            </h3>
            <p className="text-gray-500 text-sm leading-relaxed max-w-xs">
              A premium space for high-quality storytelling. Built by developers, for creators.
            </p>
          </div>

          {/* Contact Details */}
          <div>
            <h4 className="font-bold text-gray-900 mb-6 uppercase text-[10px] tracking-[0.2em]">Reach Out</h4>
            <ul className="space-y-4">
              <SocialLink 
                href="mailto:mudumalanithin6@gmail.com"
                text="mudumalanithin6@gmail.com"
                icon={
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                }
              />
              <SocialLink 
                href="tel:+919390020739"
                text="+91 9390020739"
                icon={
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                  </svg>
                }
              />
            </ul>
          </div>

          {/* Developer Section */}
          <div>
            <h4 className="font-bold text-gray-900 mb-6 uppercase text-[10px] tracking-[0.2em]">Developer</h4>
            <ul className="space-y-4">
              <SocialLink 
                href="https://github.com/nithin-6546"
                text="GitHub Profile"
                icon={
                  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                    <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                  </svg>
                }
              />
              <SocialLink 
                href="#"
                text="Portfolio"
                isExternal={false}
                icon={
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                  </svg>
                }
              />
            </ul>
          </div>

          {/* Newsletter / Tech Stack Info */}
          <div>
            <h4 className="font-bold text-gray-900 mb-6 uppercase text-[10px] tracking-[0.2em]">Build Info</h4>
            <div className="bg-gray-50 rounded-2xl p-4 border border-gray-100">
              <p className="text-[10px] text-gray-400 font-bold uppercase mb-2">Powered By</p>
              <div className="flex flex-wrap gap-2">
                <span className="px-2 py-1 bg-white border border-gray-200 rounded text-[10px] font-bold text-gray-600">React</span>
                <span className="px-2 py-1 bg-white border border-gray-200 rounded text-[10px] font-bold text-gray-600">Tailwind</span>
                <span className="px-2 py-1 bg-white border border-gray-200 rounded text-[10px] font-bold text-gray-600">Node.js</span>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 border-t border-gray-100 flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-gray-400 text-[10px] font-bold uppercase tracking-wider">
            &copy; {currentYear} Nithin Mudumala. 
          </p>
          <div className="flex gap-6">
            <a href="#" className="text-[10px] font-bold text-gray-400 hover:text-gray-900 transition-colors uppercase tracking-widest">Privacy</a>
            <a href="#" className="text-[10px] font-bold text-gray-400 hover:text-gray-900 transition-colors uppercase tracking-widest">Terms</a>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default Footer;