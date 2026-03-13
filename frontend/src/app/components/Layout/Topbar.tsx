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
        <nav className="bg-white dark:bg-gray-800">
            <div className="flex justify-end w-full">
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
        </nav>
    );
}