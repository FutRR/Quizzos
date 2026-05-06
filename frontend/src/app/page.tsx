import Link from "next/link";

export default function Home() {
  return (
    <div className="min-h-screen">
      <main className="px-4">
        <h1 className="text-3xl font-bold mb-6">Bienvenue sur Quizzy!</h1>
        <p className="text-lg mb-4">
          La meilleure plateforme de jeux en ligne pour tous les âges
        </p>
        <div className="mb-6">
          <Link
            href="/quizzes"
            className="inline-block rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
          >
            Explorer les Quiz
          </Link>
          <Link
            href="/game/impostor"
            className="inline-block rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
          >
            Jeu de l'imposteur
          </Link>
        </div>
      </main>
    </div>
  );
}
