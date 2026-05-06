"use client";

import { Tag } from "@/app/types/tagTypes";
import Link from "next/link";
import TagBadge from "../Tag/TagBadge";

interface QuizCardProps {
  quizData: {
    id: string;
    title: string;
    description: string;
    authorName: string;
    tags: Tag[];
    imageUrl?: string;
  };
}

export default function QuizCard({ quizData }: QuizCardProps) {
  const quiz = {
    id: quizData.id,
    title: quizData.title,
    description: quizData.description,
    authorName: quizData.authorName,
    tags: quizData.tags,
    imageUrl: quizData.imageUrl,
  };

  return (
    <Link href={`/quizzes/${quiz.id}`} className="group block">
      <div className="relative rounded-xl overflow-hidden bg-slate-800 
                      hover:shadow-2xl hover:shadow-blue-500/10 
                      hover:scale-[1.02] transition-all duration-300">
        <img
          src={quiz.imageUrl || ""}
          alt={`Quiz de ${quiz.authorName} sur ${quiz.title}`}
          className="w-full aspect-[4/3] object-cover brightness-90 
                     group-hover:brightness-100 transition-all duration-300"
          onError={(e) => {
            e.currentTarget.style.display = "none";
          }}
        />

        {/* Overlay gradient */}
        <div className="absolute inset-0 bg-gradient-to-t from-black/90 via-black/50 to-transparent" />

        {/* Contenu superposé */}
        <div className="absolute inset-0 p-5 flex flex-col justify-between">
          {/* Titre et auteur */}
          <div className="text-white">
            <h2 className="text-2xl font-bold mb-1.5 line-clamp-2">{quiz.title}</h2>
            <span
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                window.location.href = "/profile/" + quiz.authorName;
              }}
              className="text-sm text-gray-300 hover:text-white cursor-pointer 
                         inline-flex items-center gap-1.5 transition-colors"
            >
              <UserIcon className="w-3.5 h-3.5" />
              {quiz.authorName}
            </span>
          </div>

          {/* Tags */}
          <div className="flex flex-wrap gap-2">
            {quiz.tags.slice(0, 3).map((tag) => (
              <TagBadge key={tag.id} tag={tag} size="sm" />
            ))}
            {quiz.tags.length > 3 && (
              <span className="px-2 py-0.5 text-xs font-medium text-white/70 bg-white/10 rounded-full">
                +{quiz.tags.length - 3}
              </span>
            )}
          </div>
        </div>
      </div>
    </Link>
  );
}

// User icon
const UserIcon = ({ className }: { className?: string }) => (
  <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
  </svg>
);
