"use client";

import { useState } from "react";
import { useQuiz } from "@/app/hooks/useQuiz";
import { useRouter } from "next/navigation";
import TagInput from "../Tag/TagInput";
import ImageUpload from "../Images/ImageUpload";
import { Tag } from "@/app/types/tagTypes";
import AddQuestionModal from "../Question/AddQuestionModal";

export default function CreateQuizz() {
  const router = useRouter();
  const { createQuiz, loading, error } = useQuiz();

  // Etats pour les champs du formulaire
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [difficulty, setDifficulty] = useState("");
  const [selectedTags, setSelectedTags] = useState<Tag[]>([]);
  const [imageUrl, setImageUrl] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [createdQuizId, setCreatedQuizId] = useState<string | null>(null);

  const handleSubmit = async (e: React.SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      const newQuiz = await createQuiz({
        title,
        description,
        difficulty,
        tagIds: selectedTags.map((tag) => tag.id),
        imageUrl,
      });
      if (newQuiz) {
        setCreatedQuizId(newQuiz.id);
        setShowModal(true);
      }
    } catch {
      // error is already set in useQuiz state
    }
  };

  const handleModalClose = () => {
    setShowModal(false);
    if (createdQuizId) {
      router.push(`/quizzes/${createdQuizId}`);
    }
  };

  const cardClass =
    "rounded-3xl border border-slate-800/80 bg-slate-900/80 shadow-2xl shadow-black/20 backdrop-blur-xl";
  const fieldLabelClass = "text-sm font-medium text-slate-200";
  const fieldClass =
    "mt-2 w-full rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-white placeholder:text-slate-500 transition focus:border-blue-500 focus:outline-none focus:ring-4 focus:ring-blue-500/20";
  const selectClass =
    "mt-2 w-full rounded-2xl border border-slate-700 bg-slate-950/70 px-4 py-3 text-sm text-white transition focus:border-blue-500 focus:outline-none focus:ring-4 focus:ring-blue-500/20";
  const sectionPillClass =
    "inline-flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-500 text-sm font-semibold text-white shadow-lg shadow-blue-500/20";

  return (
    <>
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-6 text-white">
        <header className={`${cardClass} overflow-hidden`}> 
          <div className="bg-gradient-to-r from-blue-600/20 via-indigo-500/10 to-cyan-500/20 p-6 md:p-8">
            <div className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
              <div className="max-w-2xl space-y-3">
                <p className="text-xs font-semibold uppercase tracking-[0.35em] text-blue-200/80">
                  Quiz builder
                </p>
                <h1 className="text-3xl font-bold tracking-tight text-white md:text-4xl">
                  Créer un nouveau quiz
                </h1>
                <p className="text-sm leading-6 text-slate-300 md:text-base">
                  Structurez votre quiz en quelques étapes : informations générales,
                  tags, illustration et validation finale.
                </p>
              </div>

              <div className="grid grid-cols-3 gap-3 text-left md:min-w-[320px]">
                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                  <p className="text-xs uppercase tracking-wider text-slate-400">Étape 1</p>
                  <p className="mt-1 text-sm font-semibold text-white">Infos</p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                  <p className="text-xs uppercase tracking-wider text-slate-400">Étape 2</p>
                  <p className="mt-1 text-sm font-semibold text-white">Tags</p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                  <p className="text-xs uppercase tracking-wider text-slate-400">Étape 3</p>
                  <p className="mt-1 text-sm font-semibold text-white">Visuel</p>
                </div>
              </div>
            </div>
          </div>
        </header>

        {error && (
          <div className="rounded-2xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {error}
          </div>
        )}

        {loading && (
          <div className="rounded-2xl border border-blue-500/30 bg-blue-500/10 px-4 py-3 text-sm text-blue-100">
            Création du quiz en cours...
          </div>
        )}

        <form onSubmit={handleSubmit} className="grid gap-6">
          <section className={cardClass}>
            <div className="border-b border-slate-800 px-6 py-5 md:px-8">
              <div className="flex items-center gap-4">
                <span className={sectionPillClass}>1</span>
                <div>
                  <h2 className="text-lg font-semibold text-white">Informations du quiz</h2>
                  <p className="text-sm text-slate-400">
                    Donnez un nom clair et une description engageante.
                  </p>
                </div>
              </div>
            </div>

            <div className="grid gap-5 px-6 py-6 md:px-8">
              <div className="grid gap-5 md:grid-cols-2">
                <div>
                  <label className={fieldLabelClass} htmlFor="quiz-title">
                    Titre
                  </label>
                  <input
                    id="quiz-title"
                    type="text"
                    placeholder="Ex. Culture générale 2026"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    className={fieldClass}
                  />
                </div>

                <div>
                  <label className={fieldLabelClass} htmlFor="quiz-difficulty">
                    Difficulté
                  </label>
                  <select
                    id="quiz-difficulty"
                    value={difficulty}
                    onChange={(e) => setDifficulty(e.target.value)}
                    className={selectClass}
                  >
                    <option value="">Choisir une difficulté</option>
                    <option value="Easy">Facile</option>
                    <option value="Medium">Moyen</option>
                    <option value="Hard">Difficile</option>
                  </select>
                </div>

                <div className="md:col-span-2">
                  <label className={fieldLabelClass} htmlFor="quiz-description">
                    Description
                  </label>
                  <textarea
                    id="quiz-description"
                    placeholder="Décrivez le thème, le ton ou les règles du quiz..."
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    rows={4}
                    className={`${fieldClass} resize-none`}
                  />
                </div>
              </div>
            </div>
          </section>

          <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
            <div className={cardClass}>
              <div className="border-b border-slate-800 px-6 py-5 md:px-8">
                <div className="flex items-center gap-4">
                  <span className={sectionPillClass}>2</span>
                  <div>
                    <h2 className="text-lg font-semibold text-white">Tags</h2>
                    <p className="text-sm text-slate-400">
                      Ajoutez jusqu’à 5 tags pour mieux organiser votre quiz.
                    </p>
                  </div>
                </div>
              </div>

              <div className="px-6 py-6 md:px-8">
                <TagInput
                  selectedTags={selectedTags}
                  onTagsChange={setSelectedTags}
                  maxTags={5}
                  placeholder="Ajouter des tags..."
                />
              </div>
            </div>

            <div className={cardClass}>
              <div className="border-b border-slate-800 px-6 py-5 md:px-8">
                <div className="flex items-center gap-4">
                  <span className={sectionPillClass}>3</span>
                  <div>
                    <h2 className="text-lg font-semibold text-white">Image de couverture</h2>
                    <p className="text-sm text-slate-400">
                      Une image soignée renforce l’identité de votre quiz.
                    </p>
                  </div>
                </div>
              </div>

              <div className="px-6 py-6 md:px-8">
                <ImageUpload
                  onImageUploaded={setImageUrl}
                  currentImageUrl={imageUrl}
                />
              </div>
            </div>
          </section>

          <section className={`${cardClass} border-blue-500/20 bg-gradient-to-r from-blue-500/10 via-indigo-500/10 to-cyan-500/10`}>
            <div className="flex flex-col gap-5 px-6 py-6 md:flex-row md:items-center md:justify-between md:px-8">
              <div className="max-w-2xl space-y-2">
                <h2 className="text-xl font-semibold text-white">Prêt à créer votre quiz ?</h2>
                <p className="text-sm leading-6 text-slate-300">
                  Une fois le quiz créé, vous pourrez immédiatement ajouter des questions depuis la fenêtre qui s’ouvrira.
                </p>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="inline-flex items-center justify-center rounded-2xl bg-gradient-to-r from-blue-500 to-indigo-500 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-blue-500/30 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? "Création..." : "Créer le quiz"}
              </button>
            </div>
          </section>
        </form>

      </div>

      {createdQuizId && (
        <AddQuestionModal
          isOpen={showModal}
          onClose={handleModalClose}
          quizId={createdQuizId}
        />
      )}
    </>
  );
}
