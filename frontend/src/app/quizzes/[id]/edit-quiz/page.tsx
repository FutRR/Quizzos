"use client";
import { use } from "react";
import Link from "next/link";
import EditQuizz from "@/app/components/Quizz/EditQuizz";

export default function EditQuiz({params}: {params: Promise<{id: string}>}) {
    const { id } = use(params);

    return (
        <div className="mx-auto max-w-6xl space-y-8">
            <div className="relative overflow-hidden rounded-3xl border border-gray-800 bg-gradient-to-br from-slate-950 via-gray-900 to-indigo-950 p-6 shadow-2xl sm:p-8">
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(99,102,241,0.18),transparent_35%),radial-gradient(circle_at_bottom_left,rgba(236,72,153,0.12),transparent_30%)]" />
                <div className="relative flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
                    <div className="max-w-2xl space-y-4">
                        <div className="inline-flex items-center gap-2 rounded-full border border-indigo-400/20 bg-indigo-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-indigo-300">
                            <span className="h-2 w-2 rounded-full bg-indigo-400" />
                            Édition du quiz
                        </div>
                        <div className="space-y-3">
                            <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
                                Donnez une nouvelle vie à votre quiz
                            </h1>
                            <p className="max-w-xl text-sm leading-6 text-gray-300 sm:text-base">
                                Ajustez le titre, la description, l’image, les tags et les questions dans une interface claire, moderne et confortable.
                            </p>
                        </div>
                    </div>

                    <div className="flex flex-wrap gap-3">
                        <Link
                            href={`/quizzes/${id}`}
                            className="inline-flex items-center gap-2 rounded-xl border border-gray-700 bg-white/5 px-4 py-2.5 text-sm font-semibold text-gray-200 transition-colors hover:bg-white/10 hover:text-white"
                        >
                            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                            </svg>
                            Retour au quiz
                        </Link>
                    </div>
                </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-[280px_minmax(0,1fr)]">
                <aside className="space-y-4 rounded-3xl border border-gray-800 bg-gray-900/70 p-6 shadow-xl backdrop-blur">
                    <div className="flex items-center gap-3">
                        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-indigo-500/15 text-indigo-300 ring-1 ring-inset ring-indigo-400/20">
                            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M11.42 15.17a1.5 1.5 0 012.12 0l5.59 5.59a1.5 1.5 0 01-2.12 2.12l-5.59-5.59a1.5 1.5 0 010-2.12z" />
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4.5 13.5a9 9 0 1118 0 9 9 0 01-18 0z" />
                            </svg>
                        </div>
                        <div>
                            <p className="text-sm font-semibold text-white">Conseils rapides</p>
                            <p className="text-xs text-gray-400">Optimisez votre contenu avant publication</p>
                        </div>
                    </div>

                    <div className="space-y-3">
                        <div className="rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
                            <p className="text-sm font-medium text-white">Structure claire</p>
                            <p className="mt-1 text-sm leading-6 text-gray-400">
                                Travaillez d’abord les informations générales, puis ajustez les questions et réponses.
                            </p>
                        </div>
                        <div className="rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
                            <p className="text-sm font-medium text-white">Visuel cohérent</p>
                            <p className="mt-1 text-sm leading-6 text-gray-400">
                                Une image de couverture et des tags pertinents améliorent la lisibilité du quiz.
                            </p>
                        </div>
                        <div className="rounded-2xl border border-gray-800 bg-gray-950/60 p-4">
                            <p className="text-sm font-medium text-white">Validation finale</p>
                            <p className="mt-1 text-sm leading-6 text-gray-400">
                                Vérifiez les réponses correctes et les types de questions avant d’enregistrer.
                            </p>
                        </div>
                    </div>
                </aside>

                <section className="overflow-hidden rounded-3xl border border-gray-800 bg-gray-900/80 shadow-2xl backdrop-blur">
                    <div className="border-b border-gray-800 bg-white/5 px-6 py-4 sm:px-8">
                        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                            <div>
                                <h2 className="text-lg font-semibold text-white">Formulaire d’édition</h2>
                                <p className="text-sm text-gray-400">Modifiez votre quiz sans quitter cette page.</p>
                            </div>
                            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-semibold text-emerald-300">
                                <span className="h-2 w-2 rounded-full bg-emerald-400" />
                                Contenu modifiable
                            </div>
                        </div>
                    </div>

                    <div className="p-4 sm:p-6 lg:p-8">
                        <EditQuizz quizId={id} />
                    </div>
                </section>
            </div>
        </div>
    );
}