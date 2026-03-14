"use client";

import Topbar from "./Topbar";
import Sidebar from "./Sidebar";

interface MainLayoutProps {
    children: React.ReactNode;
}

export default function MainLayout({ children }: MainLayoutProps) {
    return (
        <div className="flex flex-col min-h-screen bg-stone-100 dark:bg-slate-900">
            { <Topbar /> }
            { <Sidebar />}
            <main className="flex-1 lg:ml-64">
                {/* Top padding for mobile menu button */}
                <div className="lg:hidden h-16" />
                <div className="p-4 lg:px-6 lg:py-6">
                    {children}
                </div>
            </main>
        </div>
    );
}