"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/app/hooks/useAuth";

interface NavItem {
  name: string;
  href: string;
  icon: React.ReactNode;
}

const navItems: NavItem[] = [
  {
    name: "Accueil",
    href: "/",
    icon: (
      <svg
        className="w-5 h-5"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"
        />
      </svg>
    ),
  },
  {
    name: "Quiz",
    href: "/quizzes",
    icon: (
      <svg
        className="w-5 h-5"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
        />
      </svg>
    ),
  },
  {
    name: "Profil",
    href: "/profile",
    icon: (
      <svg
        className="w-5 h-5"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"
        />
      </svg>
    ),
  },
];

export default function Sidebar() {
  const [isOpen, setIsOpen] = useState(false);
  const pathname = usePathname();

  const { user, logout } = useAuth();
  const isActive = (href: string) => pathname === href;

  return (
    <>
      {/* Mobile menu button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-white shadow-lg hover:bg-gray-100 transition-colors"
        aria-label="Toggle menu"
      >
        {isOpen ? (
          <svg
            className="w-6 h-6 text-gray-700"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        ) : (
          <svg
            className="w-6 h-6 text-gray-700"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M4 6h16M4 12h16M4 18h16"
            />
          </svg>
        )}
      </button>

      {/* Overlay for mobile */}
      {isOpen && (
        <div
          className="lg:hidden fixed inset-0 bg-black/50 z-30"
          onClick={() => setIsOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
                    fixed top-0 left-0 z-40 flex flex-col h-screen w-64 bg-gray-900 
                    border-r border-gray-700
                    transform transition-transform duration-300 ease-in-out
                    lg:translate-x-0
                    ${isOpen ? "translate-x-0" : "-translate-x-full"}
                `}
      >
        {/* Logo */}
        <div className="h-16 flex items-center px-6">
          <Link href="/" className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-lg">Q</span>
            </div>
            <span className="text-xl font-bold text-white">Quizzos</span>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 flex flex-col justify-between h-50% px-4 py-6 space-y-1 overflow-y-auto">
          <div className="flex flex-col space-y-1">
            {navItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setIsOpen(false)}
                className={`
                                    flex items-center px-4 py-3 rounded-lg transition-all duration-200
                                    ${
                                      isActive(item.href)
                                        ? "bg-blue-900/50 text-blue-400 font-medium"
                                        : "text-gray-400 hover:bg-gray-800 hover:text-white"
                                    }
                                `}
              >
                <span
                  className={
                    isActive(item.href) ? "text-blue-400" : "text-gray-500"
                  }
                >
                  {item.icon}
                </span>
                <span className="ml-3">{item.name}</span>
                {isActive(item.href) && (
                  <span className="ml-auto w-1.5 h-1.5 bg-blue-400 rounded-full" />
                )}
              </Link>
            ))}
          </div>

          {user ? (
            <div>
              <Link
                href={"/login"}
                onClick={logout}
                className={`
                                    flex items-center px-4 py-3 rounded-lg transition-all duration-200
                                    ${
                                      isActive("/login")
                                        ? "bg-blue-900/50 text-blue-400 font-medium"
                                        : "text-gray-400 hover:bg-gray-800 hover:text-white"
                                    }
                                `}
              >
                <span className="text-gray-500 mr-2">
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    viewBox="0 0 512 512"
                    className="w-5 h-5 sm:w-6 sm:h-6"
                    fill="currentColor"
                  >
                    <path
                      opacity="0.4"
                      d="M256 464c114.9 0 208-93.1 208-208S370.9 48 256 48V16c132.5 0 240 107.5 240 240S388.5 496 256 496s-240-107.5-240-240c0-65.1 25.9-124.2 68-167.6l22.6 22.6C68.9 147.8 48 199.4 48 256c0 114.9 93.1 208 208 208z"
                    />
                    <path d="M256 16V48c-56.6 0-108.2 20.9-147.4 55.4L86 80.8C129.8 41.9 190.3 16 256 16zM374.6 246.6l-128-128c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3L265.4 228H32c-17.7 0-32 14.3-32 32s14.3 32 32 32H265.4l-64.1 64.1c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0l128-128c12.5-12.5 12.5-32.8 0-45.3z" />
                  </svg>
                </span>
                Déconnexion
              </Link>
            </div>
          ) : (
            <div className="space-y-1">
              <Link
                href={"/login"}
                className={`
                                    flex items-center px-4 py-3 rounded-lg transition-all duration-200
                                    ${
                                      isActive("/login")
                                        ? "bg-blue-900/50 text-blue-400 font-medium"
                                        : "text-gray-400 hover:bg-gray-800 hover:text-white"
                                    }
                                `}
              >
                <span className="ml-3">Connexion</span>
                {isActive("/login") && (
                  <span className="ml-auto w-1.5 h-1.5 bg-blue-400 rounded-full" />
                )}
              </Link>
              <Link
                href={"/register"}
                className={`
                                    flex items-center px-4 py-3 rounded-lg transition-all duration-200
                                    ${
                                      isActive("/register")
                                        ? "bg-blue-900/50 text-blue-400 font-medium"
                                        : "text-gray-400 hover:bg-gray-800 hover:text-white"
                                    }
                                `}
              >
                <span className="ml-3">Inscription</span>
                {isActive("/register") && (
                  <span className="ml-auto w-1.5 h-1.5 bg-blue-400 rounded-full" />
                )}
              </Link>
            </div>
          )}
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-gray-700">
          <div className="flex items-center px-4 py-3 text-sm text-gray-500">
            <svg
              className="w-5 h-5 mr-3 text-gray-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <span>Quizzos v0.2</span>
          </div>
        </div>
      </aside>
    </>
  );
}
