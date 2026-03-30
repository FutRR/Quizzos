"use client";

import { useState, useEffect, useRef } from "react";
import { Tag } from "@/app/types/tagTypes";
import { tagService } from "@/app/services/tagService";
import TagBadge from "./TagBadge";

interface TagInputProps {
  selectedTags: Tag[];
  onTagsChange: (tags: Tag[]) => void;
  maxTags?: number;
  placeholder?: string;
}

export default function TagInput({
  selectedTags,
  onTagsChange,
  maxTags = 5,
  placeholder = "Rechercher ou créer un tag...",
}: TagInputProps) {
  const [query, setQuery] = useState("");
  const [suggestions, setSuggestions] = useState<Tag[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);
  const [allTags, setAllTags] = useState<Tag[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Charger tous les tags au montage
  useEffect(() => {
    const loadTags = async () => {
      try {
        const tags = await tagService.getAllTags();
        setAllTags(tags);
      } catch (error) {
        console.error("Error loading tags:", error);
      }
    };
    loadTags();
  }, []);

  // Rechercher les tags
  useEffect(() => {
    if (query.trim().length === 0) {
      setSuggestions(
        allTags.filter((t) => !selectedTags.some((st) => st.id === t.id)),
      );
      return;
    }

    const filtered = allTags.filter(
      (t) =>
        t.name.toLowerCase().includes(query.toLowerCase()) &&
        !selectedTags.some((st) => st.id === t.id),
    );
    setSuggestions(filtered);
  }, [query, allTags, selectedTags]);

  // Fermer le dropdown quand on clique ailleurs
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node) &&
        inputRef.current &&
        !inputRef.current.contains(event.target as Node)
      ) {
        setShowDropdown(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleSelectTag = (tag: Tag) => {
    if (selectedTags.length < maxTags) {
      onTagsChange([...selectedTags, tag]);
      setQuery("");
      setShowDropdown(false);
    }
  };

  const handleRemoveTag = (tagId: number) => {
    onTagsChange(selectedTags.filter((t) => t.id !== tagId));
  };

  const handleCreateTag = async () => {
    if (query.trim().length < 2) return;

    setIsLoading(true);
    try {
      const newTag = await tagService.createTag({
        name: query.trim().toLowerCase(),
        color: getRandomColor(),
      });
      setAllTags([...allTags, newTag]);
      handleSelectTag(newTag);
    } catch (error) {
      console.error("Error creating tag:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const getRandomColor = () => {
    const colors = [
      "#ef4444",
      "#f97316",
      "#f59e0b",
      "#eab308",
      "#84cc16",
      "#22c55e",
      "#10b981",
      "#14b8a6",
      "#06b6d4",
      "#0ea5e9",
      "#3b82f6",
      "#6366f1",
      "#8b5cf6",
      "#a855f7",
      "#d946ef",
      "#ec4899",
      "#f43f5e",
    ];
    return colors[Math.floor(Math.random() * colors.length)];
  };

  const canCreateTag =
    query.trim().length >= 2 &&
    !allTags.some((t) => t.name.toLowerCase() === query.trim().toLowerCase());

  return (
    <div className="relative">
      {/* Tags sélectionnés */}
      {selectedTags.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-2">
          {selectedTags.map((tag) => (
            <TagBadge
              key={tag.id}
              tag={tag}
              onRemove={() => handleRemoveTag(tag.id)}
              size="md"
            />
          ))}
        </div>
      )}

      {/* Input de recherche */}
      {selectedTags.length < maxTags && (
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <svg
              className="w-4 h-4 text-gray-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"
              />
            </svg>
          </div>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onFocus={() => setShowDropdown(true)}
            placeholder={placeholder}
            className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg 
                                 text-white placeholder-gray-400 text-sm
                                 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
      )}

      {/* Dropdown des suggestions */}
      {showDropdown && selectedTags.length < maxTags && (
        <div
          ref={dropdownRef}
          className="absolute z-10 w-full mt-1 bg-gray-800 border border-gray-700 rounded-lg shadow-lg max-h-48 overflow-y-auto"
        >
          {isLoading ? (
            <div className="p-3 text-center text-gray-400 text-sm">
              Chargement...
            </div>
          ) : (
            <>
              {suggestions.map((tag) => (
                <button
                  key={tag.id}
                  type="button"
                  onClick={() => handleSelectTag(tag)}
                  className="w-full px-3 py-2 text-left hover:bg-gray-700 flex items-center gap-2 transition-colors"
                >
                  <span
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: tag.color || "#6366f1" }}
                  />
                  <span className="text-white text-sm">#{tag.name}</span>
                </button>
              ))}

              {canCreateTag && (
                <button
                  type="button"
                  onClick={handleCreateTag}
                  className="w-full px-3 py-2 text-left hover:bg-gray-700 flex items-center gap-2 
                                             border-t border-gray-700 text-blue-400 transition-colors"
                >
                  <svg
                    className="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 6v6m0 0v6m0-6h6m-6 0H6"
                    />
                  </svg>
                  <span className="text-sm">
                    Créer &quot;{query.trim()}&quot;
                  </span>
                </button>
              )}

              {suggestions.length === 0 && !canCreateTag && (
                <div className="p-3 text-center text-gray-400 text-sm">
                  Aucun tag trouvé
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Indicateur de limite */}
      <p className="mt-1 text-xs text-gray-500">
        {selectedTags.length}/{maxTags} tags
      </p>
    </div>
  );
}
