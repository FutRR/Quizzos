"use client";

import { Tag } from "@/app/types/tagTypes";

interface TagBadgeProps {
    tag: Tag;
    onClick?: () => void;
    onRemove?: () => void;
    size?: "sm" | "md";
}

export default function TagBadge({ tag, onClick, onRemove, size = "sm" }: TagBadgeProps) {
    const sizeClasses = size === "sm" 
        ? "px-2 py-0.5 text-xs" 
        : "px-3 py-1 text-sm";

    return (
        <span
            onClick={onClick}
            style={{ backgroundColor: tag.color || "#6366f1" }}
            className={`${sizeClasses} font-medium text-white rounded-full inline-flex items-center gap-1
                       ${onClick ? "cursor-pointer hover:opacity-80" : ""} transition-opacity`}
        >
            #{tag.name}
            {onRemove && (
                <button
                    type="button"
                    onClick={(e) => {
                        e.stopPropagation();
                        onRemove();
                    }}
                    className="ml-1 hover:bg-white/20 rounded-full p-0.5 transition-colors"
                >
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            )}
        </span>
    );
}
