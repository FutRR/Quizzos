import Link from "next/link";
import QuizCard from "./components/Cards/QuizCard";
export default function Home() {
  return (
    <div className="">
      <main className="">
        <h1 className="text-3xl font-bold mb-6">Bienvenue sur Quizzy!</h1>
        <p className="text-lg mb-4">Découvrez, jouez et créez des quiz sur une variété de sujets. Rejoignez notre communauté de passionnés de quiz dès aujourd'hui!</p>
        <div className="mb-6">
          <Link href="/quizzes" className="inline-block rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">Explorer les Quiz</Link>
        </div>
        <QuizCard />
        <p>Feed</p>
      </main>
    </div>
  );
}
