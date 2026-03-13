"use client";

import { useJsonPlaceholder } from "@/app/hooks/useJsonPlaceholder";

export default function QuizCard() {
    const { user, images, loading } = useJsonPlaceholder();

  // TODO: Remplacer par les données du quiz réel
    const quiz = {
        title: "La Natation",
        authorName: user?.name || "Inconnu",
        tags: ["sport", "natation"],
        image: images?.[0]
            ? `https://picsum.photos/400/300?random=${images[0].id}&grayscale`
            : null,
        imageAlt: images?.[0]?.title || "Illustration du quiz",
    };

    return (
        <div className="mx-4">
            <div
                className="relative rounded-lg overflow-hidden
                           hover:shadow-lg transition-all duration-300
                           bg-gray-900"
            >
                {loading ? (
                    <div className="w-full aspect-[4/3] bg-gray-800 animate-pulse" />
                ) : quiz.image ? (
                    <>
                        <img
                            src={quiz.image}
                            alt={quiz.imageAlt}
                            className="w-full aspect-[4/3] object-cover brightness-50"
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
                                <h2 className="text-3xl font-bold mb-2">
                                    {quiz.title}
                                </h2>
                                <p className="text-sm opacity-90">
                                    By {quiz.authorName}
                                </p>
                            </div>
                            
                            {/* Tags en bas */}
                            <div className="flex gap-2">
                                {quiz.tags.map((tag, index) => (
                                    <span
                                        key={index}
                                        className="px-3 py-1 rounded-full text-sm font-medium
                                                   bg-white/20 backdrop-blur-sm text-white
                                                   border border-white/30"
                                    >
                                        #{tag}
                                    </span>
                                ))}
                            </div>
                        </div>
                    </>
                ) : (
                    <div className="w-full aspect-[4/3] bg-gray-800 flex items-center justify-center">
                        <span className="text-sm text-gray-400">
                            Pas d'image
                        </span>
                    </div>
                )}
            </div>
        </div>
    );
}