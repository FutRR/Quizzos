"use client";

import Topbar from "./Topbar";

interface MainLayoutProps {
    children: React.ReactNode;
}

export default function MainLayout({ children }: MainLayoutProps) {
    return (
        <div className="flex min-h-screen bg-gray-100 dark:bg-gray-900">
            { <Topbar /> }
            {/* <Sidebar /> */}
            <main className="flex-1 lg:ml-64">
                {/* Top padding for mobile menu button */}
                <div className="lg:hidden h-16" />
                <div className="p-4 lg:px-6 lg:py-6">
                    <div className="mb-4">
                        <div className="mx-auto w-full max-w-3xl">
                            {/* <SearchBar /> */}
                        </div>
                    </div>
                    {children}
                </div>
            </main>
        </div>
    );
}