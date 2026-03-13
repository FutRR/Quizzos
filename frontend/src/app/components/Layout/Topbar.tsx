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
    const pathname = usePathname();

    const isActive = (href: string) => pathname === href;

    return (
        <nav className="bg-gray-100 dark:bg-gray-900 border-b border-gray-700">
            <div className="flex justify-end w-full">
                {navItems.map((item) => (
                    <Link
                        key={item.href}
                        href={item.href}
                        className={`
                            flex items-center px-4 py-3 rounded-lg transition-all duration-200
                            ${isActive(item.href)
                                ? "text-blue-400 font-medium"
                                : "text-gray-400 hover:text-white"
                            }
                        `}
                        >
                            {item.name}
                    </Link>
                ))}
            </div>
        </nav>
    );
}