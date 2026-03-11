import Link from "next/link";

export default function DashboardPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 font-sans dark:bg-black">
      <main className="w-full max-w-3xl rounded-2xl border border-zinc-200 bg-white p-10 dark:border-zinc-800 dark:bg-black">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="mt-3 text-zinc-600 dark:text-zinc-400">
          Connexion réussie. Page à construire.
        </p>
        <Link
          href="/profile"
          className="mt-5 inline-block rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
        >
          Voir le profil
        </Link>
      </main>
    </div>
  );
}