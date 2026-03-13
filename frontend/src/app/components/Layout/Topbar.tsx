"use client";

import { useAuth } from "@/app/hooks/useAuth";
import Link from "next/link";
import { usePathname } from "next/navigation";


// interface NavItem {
//     name: string;
//     href: string;
// }

// const navItems: NavItem[] = [
//     {
//         name: "Inscription",
//         href:"/register",
//     },
//     {
//         name: "Connexion",
//         href:"/login",
//     }
// ];

export default function Topbar() {
    const pathname = usePathname();

    const { user, logout } = useAuth();
    const isActive = (href: string) => pathname === href;

    return (
        <nav className="bg-gray-100 dark:bg-gray-900 sticky top-0">
            <div className="flex justify-end w-full">
                {/* {!user && (
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
                    ))
                )} */}
            </div>
        </nav>
    );
}