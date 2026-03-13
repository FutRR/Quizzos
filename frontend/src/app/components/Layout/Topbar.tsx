"use client";

import { useAuth } from "@/app/hooks/useAuth";
import Link from "next/link";
import { usePathname } from "next/navigation";


interface NavItem {
    name: string;
    href: string;
}

const navItems: NavItem[] = [
    {
        name: "Inscription",
        href:"/register",
    },
    {
        name: "Connexion",
        href:"/login",
    }
];

export default function Topbar() {
    const pathname = usePathname();

    const { user, logout } = useAuth();
    const isActive = (href: string) => pathname === href;

    return (
        <nav className="bg-gray-100 dark:bg-gray-900 sticky top-0">
            <div className="flex justify-end w-full">
                {!user && (
                    navItems.map((item) => (
                        <Link
                            key={item.name}
                            href={item.href}
                            className={`px-4 py-2 text-sm font-medium rounded-md ${
                                isActive(item.href)
                                    ? "bg-blue-600 text-white"
                                    : "text-gray-700 hover:bg-gray-200 dark:text-gray-300 dark:hover:bg-gray-700"
                            }`}
                        >
                            {item.name}
                        </Link>
<<<<<<< HEAD

                        <Link
                            href="/login"
                            className={isActive("/login") ? "text-blue-400" : "text-gray-400"}
                        >
                            Connexion
                        </Link>
                    </>
                )}

                {user && (
                    <button
                        onClick={logout}
                        className="inline-flex items-center justify-center p-3 rounded-md text-white hover:bg-gray-800 transition-colors"
                        aria-label="Déconnexion"
                    >
                        <svg
                            xmlns="http://www.w3.org/2000/svg"
                            viewBox="0 0 512 512"
                            className="w-6 h-6 sm:w-7 sm:h-7"
                            fill="currentColor"
                        >
                            <path
                                opacity="0.4"
                                d="M256 464c114.9 0 208-93.1 208-208S370.9 48 256 48V16c132.5 0 240 107.5 240 240S388.5 496 256 496s-240-107.5-240-240c0-65.1 25.9-124.2 68-167.6l22.6 22.6C68.9 147.8 48 199.4 48 256c0 114.9 93.1 208 208 208z"
                            />
                            <path d="M256 16V48c-56.6 0-108.2 20.9-147.4 55.4L86 80.8C129.8 41.9 190.3 16 256 16zM374.6 246.6l-128-128c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3L265.4 228H32c-17.7 0-32 14.3-32 32s14.3 32 32 32H265.4l-64.1 64.1c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0l128-128c12.5-12.5 12.5-32.8 0-45.3z" />
                        </svg>
                    </button>
=======
                    ))
>>>>>>> adb19c7ca6bb483092fec5693b98b2e2c8d8dee4
                )}
            </div>
        </nav>
    );
}