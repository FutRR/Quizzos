"use client";

interface QuizCardProps {
  quizData: {
    title: string;
    description: string;
    authorName: string;
    tags: { id: number; name: string; color: string }[];
    image?: string;
    imageAlt?: string;
  };
}

export default function QuizCard({ quizData }: QuizCardProps) {
  const quiz = {
    title: quizData.title,
    description: quizData.description,
    authorName: quizData.authorName,
    tags: quizData.tags,
    image: quizData.image,
    imageAlt: quizData.imageAlt,
  };

  return (
    <div>
      <div className="relative rounded-lg overflow-hidden hover:shadow-lg transition-all duration-300 bg-gray-900">
        <div className="w-full aspect-[4/3] bg-gray-800 animate-pulse" />
        {/* <img
          src={quiz.image}
          alt={quiz.imageAlt}
          className="w-full aspect-[4/3] object-cover brightness-50"
          onError={(e) => {
            e.currentTarget.style.display = "none";
          }}
        /> */}

        {/* Overlay sombre */}
        <div className="absolute inset-0 bg-gradient-to-t from-black/90 via-black/60 to-transparent" />

        {/* Contenu superposé */}
        <div className="absolute inset-0 p-6 flex flex-col justify-between">
          {/* Titre et auteur en haut */}
          <div className="text-white">
            <h2 className="text-3xl font-bold mb-2">{quiz.title}</h2>
            <p className="text-sm opacity-90">By {quiz.authorName}</p>
          </div>

          {/* Tags en bas */}
          <div className="flex gap-2">
            {quiz.tags.map((tag) => (
              <span
                key={tag.id}
                className="px-3 py-1 rounded-full text-sm font-medium bg-white/20 backdrop-blur-sm text-white border border-white/30"
              >
                #{tag.name}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
