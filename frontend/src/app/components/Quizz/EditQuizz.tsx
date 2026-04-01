"use client";

import { useState, useEffect } from "react";
import { useQuiz } from "@/app/hooks/useQuiz";
import { useRouter } from "next/navigation";
import TagInput from "../Tag/TagInput";
import ImageUpload from "../Images/ImageUpload";
import { Tag } from "@/app/types/tagTypes";

interface EditQuizzProps {
    quizId: string;
}

interface AnswerForm {
    id: number;
    value: string;
    isCorrect: boolean;
}

interface QuestionForm {
    id: number;
    text: string;
    type: string;
    answers: AnswerForm[];
    imagesUrls: string[];
}

export default function EditQuizz({ quizId }: EditQuizzProps) {
    const router = useRouter();
    const { getQuizById, updateQuiz, loading, error } = useQuiz();

    const [title, setTitle] = useState("");
    const [description, setDescription] = useState("");
    const [difficulty, setDifficulty] = useState("");
    const [selectedTags, setSelectedTags] = useState<Tag[]>([]);
    const [imageUrl, setImageUrl] = useState("");
    const [questions, setQuestions] = useState<QuestionForm[]>([]);

    useEffect(() => {
        const loadQuiz = async () => {
            try {
                const quiz = await getQuizById(quizId);

                setTitle(quiz.title);
                setDescription(quiz.description);
                setDifficulty(quiz.difficulty);
                setSelectedTags(quiz.tags || []);
                setImageUrl(quiz.imageUrl || "");
                setQuestions(
                    (quiz.questions || []).map((q: any) => ({
                        id: q.id,
                        text: q.text,
                        type: q.type,
                        answers: (q.answers || []).map((a: any) => ({
                            id: a.id,
                            value: a.value,
                            isCorrect: a.isCorrect,
                        })),
                        imagesUrls: q.imagesUrls || [],
                    }))
                );
            } catch (err) {
                console.error("Failed to load quiz:", err);
            }
        };
        loadQuiz();
    }, [quizId, getQuizById]);

    const questionCount = questions.length;
    const answerCount = questions.reduce((total, question) => total + question.answers.length, 0);
    const imageCount = questions.reduce((total, question) => total + question.imagesUrls.length, 0);

    const sectionCardClass =
        "rounded-3xl border border-gray-800 bg-gray-950/70 p-5 shadow-xl shadow-black/10 backdrop-blur sm:p-6";

    const inputClass =
        "w-full rounded-xl border border-gray-700 bg-gray-900/80 px-4 py-3 text-sm text-white placeholder:text-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20";

    const selectClass =
        "w-full rounded-xl border border-gray-700 bg-gray-900/80 px-4 py-3 text-sm text-white outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20";

    // --- Default answers per type ---
    const getDefaultAnswers = (type: string): AnswerForm[] => {
        switch (type) {
            case "TrueFalse":
                return [
                    { id: 0, value: "Vrai", isCorrect: true },
                    { id: 0, value: "Faux", isCorrect: false },
                ];
            case "ShortAnswer":
                return [{ id: 0, value: "", isCorrect: true }];
            default:
                return [];
        }
    };

    // --- Question helpers ---
    const addQuestion = () => {
        setQuestions([
            ...questions,
            {
                id: 0,
                text: "",
                type: "MultipleChoice",
                answers: getDefaultAnswers("MultipleChoice"),
                imagesUrls: [],
            },
        ]);
    };

    const removeQuestion = (index: number) => {
        setQuestions(questions.filter((_, i) => i !== index));
    };

    const updateQuestion = (index: number, field: keyof QuestionForm, value: string) => {
        const updated = [...questions];
        if (field === "type") {
            updated[index] = {
                ...updated[index],
                type: value,
                answers: getDefaultAnswers(value),
            };
        } else {
            updated[index] = { ...updated[index], [field]: value };
        }
        setQuestions(updated);
    };

    // --- Answer helpers ---
    const addAnswer = (questionIndex: number) => {
        const updated = [...questions];
        updated[questionIndex].answers = [
            ...updated[questionIndex].answers,
            { id: 0, value: "", isCorrect: false },
        ];
        setQuestions(updated);
    };

    const removeAnswer = (questionIndex: number, answerIndex: number) => {
        const updated = [...questions];
        updated[questionIndex].answers = updated[questionIndex].answers.filter(
            (_, i) => i !== answerIndex
        );
        setQuestions(updated);
    };

    const updateAnswer = (
        questionIndex: number,
        answerIndex: number,
        field: keyof AnswerForm,
        value: string | boolean
    ) => {
        const updated = [...questions];
        updated[questionIndex].answers = updated[questionIndex].answers.map(
            (a, i) => (i === answerIndex ? { ...a, [field]: value } : a)
        );
        setQuestions(updated);
    };

    // --- Image helpers ---
    const addQuestionImage = (questionIndex: number, url: string) => {
        const updated = [...questions];
        updated[questionIndex].imagesUrls = [
            ...updated[questionIndex].imagesUrls,
            url,
        ];
        setQuestions(updated);
    };

    const removeQuestionImage = (questionIndex: number, imageIndex: number) => {
        const updated = [...questions];
        updated[questionIndex].imagesUrls = updated[questionIndex].imagesUrls.filter(
            (_, i) => i !== imageIndex
        );
        setQuestions(updated);
    };

    const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        try {
            await updateQuiz(quizId, {
                title,
                description,
                difficulty,
                tagIds: selectedTags.map((tag) => tag.id),
                imageUrl,
                questions: questions.map((q) => ({
                    id: q.id,
                    text: q.text,
                    type: q.type,
                    answers: q.answers.map((a) => ({
                        id: a.id,
                        value: a.value,
                        isCorrect: a.isCorrect,
                    })),
                    imagesUrls: q.imagesUrls,
                })),
            });
            router.push(`/quizzes/${quizId}`);
        } catch {
            // error is already set in useQuiz state
        }
    };

    const inputSection = (
        <div className={sectionCardClass}>
            <div className="mb-5 flex items-start justify-between gap-4">
                <div>
                    <h2 className="text-lg font-semibold text-white">Informations générales</h2>
                    <p className="mt-1 text-sm text-gray-400">
                        Définissez l’identité et l’apparence de votre quiz.
                    </p>
                </div>
                <div className="inline-flex shrink-0 items-center justify-center rounded-full border border-indigo-500/20 bg-indigo-500/10 px-3 py-1 text-xs font-semibold leading-none whitespace-nowrap text-indigo-300">
                    Étape 1
                </div>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
                <div className="space-y-2 lg:col-span-2">
                    <label htmlFor="title" className="text-sm font-medium text-gray-200">
                        Titre
                    </label>
                    <input
                        id="title"
                        type="text"
                        placeholder="Titre du quiz"
                        value={title}
                        onChange={(e) => setTitle(e.target.value)}
                        className={inputClass}
                    />
                </div>

                <div className="space-y-2 lg:col-span-2">
                    <label htmlFor="description" className="text-sm font-medium text-gray-200">
                        Description
                    </label>
                    <input
                        id="description"
                        type="text"
                        placeholder="Description du quiz"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        className={inputClass}
                    />
                </div>

                <div className="space-y-2">
                    <label htmlFor="difficulty" className="text-sm font-medium text-gray-200">
                        Difficulté
                    </label>
                    <select
                        id="difficulty"
                        value={difficulty}
                        onChange={(e) => setDifficulty(e.target.value)}
                        className={selectClass}
                    >
                        <option value="">Sélectionner la difficulté</option>
                        <option value="Easy">Facile</option>
                        <option value="Medium">Moyen</option>
                        <option value="Hard">Difficile</option>
                    </select>
                </div>

                <div className="space-y-2">
                    <label className="text-sm font-medium text-gray-200">Statistiques</label>
                    <div className="grid grid-cols-3 gap-3">
                        <div className="rounded-2xl border border-gray-800 bg-white/5 px-3 py-3 text-center">
                            <p className="text-lg font-bold text-white">{questionCount}</p>
                            <p className="text-xs text-gray-400">Questions</p>
                        </div>
                        <div className="rounded-2xl border border-gray-800 bg-white/5 px-3 py-3 text-center">
                            <p className="text-lg font-bold text-white">{answerCount}</p>
                            <p className="text-xs text-gray-400">Réponses</p>
                        </div>
                        <div className="rounded-2xl border border-gray-800 bg-white/5 px-3 py-3 text-center">
                            <p className="text-lg font-bold text-white">{imageCount}</p>
                            <p className="text-xs text-gray-400">Images</p>
                        </div>
                    </div>
                </div>

                <div className="space-y-2 lg:col-span-2">
                    <label className="text-sm font-medium text-gray-200">Tags</label>
                    <div className="rounded-2xl border border-gray-800 bg-gray-900/60 p-4">
                        <TagInput
                            selectedTags={selectedTags}
                            onTagsChange={setSelectedTags}
                            maxTags={5}
                            placeholder="Ajouter des tags..."
                        />
                    </div>
                </div>

                <div className="space-y-2 lg:col-span-2">
                    <label className="text-sm font-medium text-gray-200">Image de couverture</label>
                    <div className="rounded-2xl border border-gray-800 bg-gray-900/60 p-4">
                        <ImageUpload
                            onImageUploaded={setImageUrl}
                            currentImageUrl={imageUrl}
                        />
                    </div>
                </div>
            </div>
        </div>
    );

    const questionsSection = (
        <div className={sectionCardClass}>
            <div className="mb-5 flex items-start justify-between gap-4">
                <div>
                    <h2 className="text-lg font-semibold text-white">Questions</h2>
                    <p className="mt-1 text-sm text-gray-400">
                        Ajoutez, modifiez ou supprimez des questions pour construire votre quiz.
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <div className="inline-flex shrink-0 items-center justify-center rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs font-semibold leading-none whitespace-nowrap text-cyan-300">
                        Étape 2
                    </div>
                    <button
                        type="button"
                        onClick={addQuestion}
                        className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-indigo-600/20 transition hover:bg-indigo-500"
                    >
                        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.5v15m7.5-7.5h-15" />
                        </svg>
                        Ajouter une question
                    </button>
                </div>
            </div>

            <div className="space-y-5">
                {questions.map((question, qIndex) => {
                    const answerTotal = question.answers.length;

                    return (
                        <div
                            key={qIndex}
                            className="rounded-2xl border border-gray-800 bg-gradient-to-br from-gray-900 to-gray-950 p-5 shadow-lg shadow-black/10 transition hover:border-gray-700"
                        >
                            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                                <div className="flex items-center gap-3">
                                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/15 text-sm font-bold text-indigo-300 ring-1 ring-inset ring-indigo-400/20">
                                        {qIndex + 1}
                                    </div>
                                    <div>
                                        <h3 className="font-semibold text-white">
                                            Question {qIndex + 1}
                                        </h3>
                                        <p className="text-xs text-gray-400">
                                            {question.type} · {answerTotal} réponse{answerTotal > 1 ? "s" : ""}
                                        </p>
                                    </div>
                                </div>

                                <button
                                    type="button"
                                    onClick={() => removeQuestion(qIndex)}
                                    className="inline-flex items-center gap-2 rounded-xl border border-rose-500/20 bg-rose-500/10 px-3 py-2 text-sm font-semibold text-rose-300 transition hover:bg-rose-500 hover:text-white"
                                >
                                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                    Supprimer
                                </button>
                            </div>

                            <div className="grid gap-4 lg:grid-cols-2">
                                <div className="space-y-2 lg:col-span-2">
                                    <label className="text-sm font-medium text-gray-200">Texte de la question</label>
                                    <input
                                        type="text"
                                        placeholder="Texte de la question"
                                        value={question.text}
                                        onChange={(e) =>
                                            updateQuestion(qIndex, "text", e.target.value)
                                        }
                                        className={inputClass}
                                    />
                                </div>

                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-gray-200">Type</label>
                                    <select
                                        value={question.type}
                                        onChange={(e) =>
                                            updateQuestion(qIndex, "type", e.target.value)
                                        }
                                        className={selectClass}
                                    >
                                        <option value="MultipleChoice">Choix multiple</option>
                                        <option value="TrueFalse">Vrai / Faux</option>
                                        <option value="ShortAnswer">Réponse courte</option>
                                    </select>
                                </div>

                                <div className="space-y-2">
                                    <label className="text-sm font-medium text-gray-200">Aperçu</label>
                                    <div className="rounded-2xl border border-gray-800 bg-white/5 px-4 py-3 text-sm text-gray-400">
                                        {answerTotal} élément{answerTotal > 1 ? "s" : ""} de réponse associé{answerTotal > 1 ? "s" : ""}
                                    </div>
                                </div>

                                <div className="lg:col-span-2 space-y-3 rounded-2xl border border-gray-800 bg-gray-950/70 p-4">
                                    <div className="flex items-center justify-between gap-3">
                                        <h4 className="text-sm font-semibold text-white">Images de la question</h4>
                                        <span className="text-xs text-gray-400">
                                            {question.imagesUrls.length} image{question.imagesUrls.length > 1 ? "s" : ""}
                                        </span>
                                    </div>

                                    {question.imagesUrls.length > 0 && (
                                        <div className="flex gap-3 overflow-x-auto pb-1">
                                            {question.imagesUrls.map((url, index) => (
                                                <div
                                                    key={index}
                                                    className="group relative h-24 w-24 flex-shrink-0 overflow-hidden rounded-2xl border border-gray-800"
                                                >
                                                    <img
                                                        className="h-full w-full object-cover"
                                                        src={url}
                                                        alt={`Image ${index + 1}`}
                                                    />
                                                    <button
                                                        type="button"
                                                        onClick={() => removeQuestionImage(qIndex, index)}
                                                        className="absolute inset-0 flex items-center justify-center bg-black/60 opacity-0 transition-opacity group-hover:opacity-100"
                                                    >
                                                        <span className="rounded-full bg-rose-500/20 px-3 py-1 text-xs font-semibold text-rose-200">
                                                            Supprimer
                                                        </span>
                                                    </button>
                                                </div>
                                            ))}
                                        </div>
                                    )}

                                    <ImageUpload
                                        onImageUploaded={(url) => addQuestionImage(qIndex, url)}
                                    />
                                </div>

                                <div className="lg:col-span-2 space-y-3 rounded-2xl border border-gray-800 bg-gray-950/70 p-4">
                                    <div className="flex items-center justify-between gap-3">
                                        <h4 className="text-sm font-semibold text-white">Réponses</h4>
                                        {question.type === "MultipleChoice" && (
                                            <button
                                                type="button"
                                                onClick={() => addAnswer(qIndex)}
                                                className="inline-flex items-center gap-2 rounded-xl border border-gray-700 bg-white/5 px-3 py-2 text-xs font-semibold text-gray-200 transition hover:bg-white/10 hover:text-white"
                                            >
                                                <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.5v15m7.5-7.5h-15" />
                                                </svg>
                                                Ajouter une réponse
                                            </button>
                                        )}
                                    </div>

                                    {question.type === "TrueFalse" && (
                                        <div className="grid gap-3 sm:grid-cols-2">
                                            {question.answers.map((answer, aIndex) => (
                                                <label
                                                    key={aIndex}
                                                    className={`flex cursor-pointer items-center gap-3 rounded-2xl border px-4 py-3 transition ${answer.isCorrect ? "border-emerald-500/30 bg-emerald-500/10" : "border-gray-800 bg-white/5 hover:bg-white/10"}`}
                                                >
                                                    <input
                                                        type="radio"
                                                        name={`tf-${qIndex}`}
                                                        checked={answer.isCorrect}
                                                        onChange={() => {
                                                            const updated = [...questions];
                                                            updated[qIndex].answers = updated[qIndex].answers.map(
                                                                (a, i) => ({ ...a, isCorrect: i === aIndex })
                                                            );
                                                            setQuestions(updated);
                                                        }}
                                                        className="radio radio-sm radio-success"
                                                    />
                                                    <span className="text-sm font-medium text-white">{answer.value}</span>
                                                </label>
                                            ))}
                                        </div>
                                    )}

                                    {question.type === "ShortAnswer" && (
                                        <div className="space-y-3">
                                            {question.answers.map((answer, aIndex) => (
                                                <div key={aIndex} className="rounded-2xl border border-gray-800 bg-white/5 p-3">
                                                    <label className="mb-2 block text-xs font-semibold uppercase tracking-[0.18em] text-gray-500">
                                                        Réponse attendue
                                                    </label>
                                                    <input
                                                        type="text"
                                                        placeholder="Réponse attendue"
                                                        value={answer.value}
                                                        onChange={(e) =>
                                                            updateAnswer(qIndex, aIndex, "value", e.target.value)
                                                        }
                                                        className={inputClass}
                                                    />
                                                </div>
                                            ))}
                                        </div>
                                    )}

                                    {question.type === "MultipleChoice" && (
                                        <div className="space-y-3">
                                            {question.answers.map((answer, aIndex) => (
                                                <div
                                                    key={aIndex}
                                                    className="grid gap-3 rounded-2xl border border-gray-800 bg-white/5 p-3 lg:grid-cols-[minmax(0,1fr)_auto_auto] lg:items-center"
                                                >
                                                    <input
                                                        type="text"
                                                        placeholder={`Réponse ${aIndex + 1}`}
                                                        value={answer.value}
                                                        onChange={(e) =>
                                                            updateAnswer(
                                                                qIndex,
                                                                aIndex,
                                                                "value",
                                                                e.target.value
                                                            )
                                                        }
                                                        className={inputClass}
                                                    />
                                                    <label className="flex items-center gap-2 rounded-xl border border-gray-800 bg-gray-950/70 px-3 py-2 text-sm text-gray-200 lg:justify-self-end">
                                                        <input
                                                            type="checkbox"
                                                            checked={answer.isCorrect}
                                                            onChange={(e) =>
                                                                updateAnswer(
                                                                    qIndex,
                                                                    aIndex,
                                                                    "isCorrect",
                                                                    e.target.checked
                                                                )
                                                            }
                                                            className="checkbox checkbox-sm checkbox-success"
                                                        />
                                                        <span>Correcte</span>
                                                    </label>
                                                    <button
                                                        type="button"
                                                        onClick={() =>
                                                            removeAnswer(qIndex, aIndex)
                                                        }
                                                        className="inline-flex items-center justify-center rounded-xl border border-gray-800 bg-gray-950/70 px-3 py-2 text-sm font-semibold text-gray-300 transition hover:border-rose-500/30 hover:bg-rose-500/10 hover:text-rose-300 lg:justify-self-end"
                                                    >
                                                        ✕
                                                    </button>
                                                </div>
                                            ))}

                                            {question.answers.length === 0 && (
                                                <div className="rounded-2xl border border-dashed border-gray-700 bg-white/5 p-4 text-sm text-gray-400">
                                                    Aucune réponse ajoutée.
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    );
                })}

                {questions.length === 0 && (
                    <div className="rounded-2xl border border-dashed border-gray-700 bg-white/5 p-8 text-center">
                        <svg className="mx-auto mb-3 h-12 w-12 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 4.5v15m7.5-7.5h-15" />
                        </svg>
                        <p className="text-sm text-gray-400">Aucune question pour le moment.</p>
                        <button
                            type="button"
                            onClick={addQuestion}
                            className="mt-4 inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-500"
                        >
                            Ajouter votre première question
                        </button>
                    </div>
                )}
            </div>
        </div>
    );

    const actionsSection = (
        <div className="rounded-3xl border border-gray-800 bg-gradient-to-br from-gray-950 to-gray-900 p-5 shadow-xl shadow-black/10 sm:p-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div>
                    <h2 className="text-lg font-semibold text-white">Finalisation</h2>
                    <p className="mt-1 text-sm text-gray-400">
                        Vérifiez les détails avant d’enregistrer les changements.
                    </p>
                </div>

                <div className="flex flex-wrap gap-3">
                    <button
                        type="button"
                        onClick={() => router.push(`/quizzes/${quizId}`)}
                        className="inline-flex items-center gap-2 rounded-xl border border-gray-700 bg-white/5 px-4 py-3 text-sm font-semibold text-gray-200 transition hover:bg-white/10 hover:text-white"
                    >
                        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                        </svg>
                        Annuler
                    </button>
                    <button
                        type="submit"
                        className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-indigo-600/20 transition hover:bg-indigo-500"
                    >
                        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                        Enregistrer les modifications
                    </button>
                </div>
            </div>
        </div>
    );

    return (
        <div className="mx-auto max-w-6xl">
            <div className="mb-6 rounded-3xl border border-gray-800 bg-gradient-to-br from-slate-950 via-gray-900 to-indigo-950 p-6 shadow-2xl sm:p-8">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                    <div className="max-w-2xl space-y-3">
                        <div className="inline-flex items-center gap-2 rounded-full border border-indigo-400/20 bg-indigo-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-indigo-300">
                            <span className="h-2 w-2 rounded-full bg-indigo-400" />
                            Interface d’édition
                        </div>
                        <div>
                            <h1 className="text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
                                Modifier votre quiz avec style
                            </h1>
                            <p className="mt-2 max-w-2xl text-sm leading-6 text-gray-300 sm:text-base">
                                Ajustez les informations générales, les médias et les questions dans un espace de travail plus clair, moderne et confortable.
                            </p>
                        </div>
                    </div>

                    <div className="grid grid-cols-3 gap-3 sm:w-fit">
                        <div className="rounded-2xl border border-gray-800 bg-white/5 px-4 py-3 text-center">
                            <p className="text-lg font-bold text-white">{questionCount}</p>
                            <p className="text-xs text-gray-400">Questions</p>
                        </div>
                        <div className="rounded-2xl border border-gray-800 bg-white/5 px-4 py-3 text-center">
                            <p className="text-lg font-bold text-white">{answerCount}</p>
                            <p className="text-xs text-gray-400">Réponses</p>
                        </div>
                        <div className="rounded-2xl border border-gray-800 bg-white/5 px-4 py-3 text-center">
                            <p className="text-lg font-bold text-white">{imageCount}</p>
                            <p className="text-xs text-gray-400">Images</p>
                        </div>
                    </div>
                </div>
            </div>

            {error && (
                <div className="mb-6 rounded-2xl border border-rose-500/20 bg-rose-500/10 p-4 text-sm text-rose-300">
                    {error}
                </div>
            )}

            {loading && (
                <div className="mb-6 rounded-2xl border border-gray-800 bg-white/5 p-4 text-sm text-gray-400">
                    Chargement...
                </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
                {inputSection}
                {questionsSection}
                {actionsSection}
            </form>
        </div>
    );
}