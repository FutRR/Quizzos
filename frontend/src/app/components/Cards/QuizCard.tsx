"use client";

import { Tag } from "@/app/types/tagTypes";
import Link from "next/link";
import { TagBadge } from "../Tag";

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
    <Link href={`/quizzes/${quiz.id}`}>
      <div className="relative rounded-lg overflow-hidden hover:shadow-lg transition-all duration-300 bg-gray-900">
        <img
          src={quiz.imageUrl || ""}
          alt={`Quiz de ${quiz.authorName} sur ${quiz.title}`}
          className="w-full aspect-[4/3] object-cover brightness-80"
          onError={(e) => {
            e.currentTarget.style.display = "none";
          }}
        />

        {/* Overlay sombre */}
        <div className="absolute inset-0 bg-gradient-to-t from-black/90 via-black/60 to-transparent" />

        {/* Contenu superposé */}
        <div className="absolute inset-0 p-6 flex flex-col justify-between">
          {/* Titre et auteur en haut */}
          <div className="text-white">
            <h2 className="text-3xl font-bold mb-2">{quiz.title}</h2>
            <Link
              href={`/profile/${quiz.authorName}`}
              className="text-sm opacity-90"
            >
              By {quiz.authorName}
            </Link>
          </div>

          {/* Tags en bas */}
          <div className="flex gap-2">
            {quiz.tags.map((tag) => (
              <TagBadge key={tag.id} tag={tag} size="md" />
              // <span
              //   style={{ backgroundColor: tag.color }}
              //   key={tag.id}
              //   className="px-3 py-1 rounded-full text-sm font-medium text-white border border-white/30"
              // >
              //   #{tag.name}
              // </span>
            ))}
          </div>
        </div>
      </div>
    </Link>
  );
}
