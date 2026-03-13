"use client";

import { useEffect } from "react";
import { useState } from "react";
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
                    <>
                        <Link
                            href="/register"
                            className={isActive("/register") ? "text-blue-400" : "text-gray-400"}
                        >
                            Inscription
                        </Link>

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
                        className="text-gray-400 hover:text-white px-4 py-3"
                    >
                        Déconnexion
                    </button>
                )}
            </div>
        </nav>
    );
}