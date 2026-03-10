import Link from "next/link";
export default function Home() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 font-sans dark:bg-black">
      <main className="flex min-h-screen w-full max-w-3xl flex-col items-center justify-between py-32 px-16 bg-white dark:bg-black sm:items-start">
        <h1 className="text-4xl font-bold">Bonjour Quizzos !</h1>
        <p className="mt-4 text-lg text-zinc-600 dark:text-zinc-400">
          Bienvenue sur votre plateforme de quiz en ligne. Connectez-vous pour accéder à vos quiz personnalisés et tester vos connaissances !
        </p>  
        <div className="mt-8 flex items-center gap-4">
          <Link
            href="/login"
            className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white dark:bg-white dark:text-black"
          >
            Login
          </Link>
          <button className="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium dark:border-zinc-800">
            Register
          </button>
        </div>
      </main>
    </div>
  );
}
