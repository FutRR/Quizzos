"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";


interface NavItem {
    name: string;
    href: string;
}

const navItems: NavItem[] = [
    {
        name: "Logo",
        href:"/",
    },
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
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const pathname = usePathname();
    
    const toggleMobileMenu = () => {
        setIsMobileMenuOpen(!isMobileMenuOpen);
    };

    return (
        <nav className="bg-white dark:bg-gray-800 shadow">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex justify-between h-16">
                    <div className="flex">
                        {navItems.map((item) => (
                            <Link
                                key={item.name}
                                href={item.href}
                                className={`px-3 py-2 rounded-md text-sm font-medium ${
                                    pathname === item.href
                                        ? "text-blue-500"
                                        : "text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"
                                }`}
                            >
                                {item.name}
                            </Link>
                        ))}
                    </div>
                </div>
            </div>  
        </nav>
    );
}