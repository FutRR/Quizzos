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

    return (
        <div className="p-6 max-w-4xl mx-auto">
            <h1 className="text-3xl font-bold mb-6">Modifier le quiz</h1>
            {error && <p className="text-red-500 mb-4">{error}</p>}
            {loading && <p className="mb-4">Chargement...</p>}
            <form onSubmit={handleSubmit} className="space-y-6">
                {/* --- Infos du quiz --- */}
                <div className="space-y-4">
                    <label htmlFor="title">Titre :</label>
                    <input
                        id="title"
                        type="text"
                        placeholder="Titre"
                        value={title}
                        onChange={(e) => setTitle(e.target.value)}
                        className="input input-bordered w-full"
                    />
                    <label htmlFor="description">Description :</label>
                    <input
                        id="description"
                        type="text"
                        placeholder="Description"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        className="input input-bordered w-full"
                    />
                    <label htmlFor="difficulty">Difficulté :</label>
                    <select
                        id="difficulty"
                        value={difficulty}
                        onChange={(e) => setDifficulty(e.target.value)}
                        className="select select-bordered w-full"
                    >
                        <option value="">Sélectionner la difficulté</option>
                        <option value="Easy">Facile</option>
                        <option value="Medium">Moyen</option>
                        <option value="Hard">Difficile</option>
                    </select>
                    <label htmlFor="tags">Tags :</label>
                    <TagInput
                        selectedTags={selectedTags}
                        onTagsChange={setSelectedTags}
                        maxTags={5}
                        placeholder="Ajouter des tags..."
                    />
                    <ImageUpload
                        onImageUploaded={setImageUrl}
                        currentImageUrl={imageUrl}
                    />
                </div>

                {/* --- Questions --- */}
                <div>
                    <div className="flex items-center justify-between mb-4">
                        <h2 className="text-xl font-bold">Questions</h2>
                        <button
                            type="button"
                            onClick={addQuestion}
                            className="btn btn-sm btn-primary"
                        >
                            + Ajouter une question
                        </button>
                    </div>

                    <div className="space-y-6">
                        {questions.map((question, qIndex) => (
                            <div
                                key={qIndex}
                                className="border rounded-lg p-4 space-y-4"
                            >
                                <div className="flex items-center justify-between">
                                    <h3 className="font-semibold">
                                        Question {qIndex + 1}
                                    </h3>
                                    <button
                                        type="button"
                                        onClick={() => removeQuestion(qIndex)}
                                        className="btn btn-sm btn-error btn-outline"
                                    >
                                        Supprimer
                                    </button>
                                </div>

                                <input
                                    type="text"
                                    placeholder="Texte de la question"
                                    value={question.text}
                                    onChange={(e) =>
                                        updateQuestion(qIndex, "text", e.target.value)
                                    }
                                    className="input input-bordered w-full"
                                />

                                <select
                                    value={question.type}
                                    onChange={(e) =>
                                        updateQuestion(qIndex, "type", e.target.value)
                                    }
                                    className="select select-bordered w-full"
                                >
                                    <option value="MultipleChoice">Choix multiple</option>
                                    <option value="TrueFalse">Vrai / Faux</option>
                                    <option value="ShortAnswer">Réponse courte</option>
                                </select>
                                                                {/* --- Images de la question --- */}
                                <div className="pl-4 space-y-3">
                                    <div className="flex items-center justify-between">
                                        <h4 className="text-sm font-medium">Images</h4>
                                    </div>
                                    {/* Images carousel */}
                                    {question.imagesUrls.length > 0 && (
                                        <div className="flex overflow-x-auto flex-nowrap bg-gray-800 p-2 rounded-lg border border-gray-700 gap-2">
                                            {question.imagesUrls.map((url, index) => (
                                                <div
                                                    key={index}
                                                    className="relative border border-gray-700 rounded-lg flex-shrink-0 w-20 h-20 overflow-hidden group"
                                                >
                                                    <img
                                                        className="w-full h-full object-cover"
                                                        src={url}
                                                        alt={`Image ${index + 1}`}
                                                    />
                                                    <button
                                                        type="button"
                                                        onClick={() => removeQuestionImage(qIndex, index)}
                                                        className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity"
                                                    >
                                                        <span className="text-red-400 text-lg">✕</span>
                                                    </button>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                    <ImageUpload
                                        onImageUploaded={(url) => addQuestionImage(qIndex, url)}
                                    />
                                </div>
                                {/* --- Réponses --- */}
                                <div className="pl-4 space-y-3">
                                    <div className="flex items-center justify-between">
                                        <h4 className="text-sm font-medium">Réponses</h4>
                                        {question.type === "MultipleChoice" && (
                                            <button
                                                type="button"
                                                onClick={() => addAnswer(qIndex)}
                                                className="btn btn-xs btn-outline"
                                            >
                                                + Ajouter une réponse
                                            </button>
                                        )}
                                    </div>

                                    {question.type === "TrueFalse" && (
                                        <div className="space-y-2">
                                            {question.answers.map((answer, aIndex) => (
                                                <label
                                                    key={aIndex}
                                                    className="flex items-center gap-3 cursor-pointer"
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
                                                    <span className="text-sm">{answer.value}</span>
                                                </label>
                                            ))}
                                        </div>
                                    )}

                                    {question.type === "ShortAnswer" && (
                                        <div>
                                            {question.answers.map((answer, aIndex) => (
                                                <input
                                                    key={aIndex}
                                                    type="text"
                                                    placeholder="Réponse attendue"
                                                    value={answer.value}
                                                    onChange={(e) =>
                                                        updateAnswer(qIndex, aIndex, "value", e.target.value)
                                                    }
                                                    className="input input-bordered input-sm w-full"
                                                />
                                            ))}
                                        </div>
                                    )}

                                    {question.type === "MultipleChoice" && (
                                        <>
                                            {question.answers.map((answer, aIndex) => (
                                                <div
                                                    key={aIndex}
                                                    className="flex items-center gap-3"
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
                                                        className="input input-bordered input-sm flex-1"
                                                    />
                                                    <label className="flex items-center gap-1 cursor-pointer">
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
                                                        <span className="text-sm">Correcte</span>
                                                    </label>
                                                    <button
                                                        type="button"
                                                        onClick={() =>
                                                            removeAnswer(qIndex, aIndex)
                                                        }
                                                        className="btn btn-xs btn-error btn-outline"
                                                    >
                                                        ✕
                                                    </button>
                                                </div>
                                            ))}

                                            {question.answers.length === 0 && (
                                                <p className="text-sm text-gray-400">
                                                    Aucune réponse ajoutée
                                                </p>
                                            )}
                                        </>
                                    )}
                                </div>
                            </div>
                        ))}

                        {questions.length === 0 && (
                            <p className="text-gray-400">Aucune question</p>
                        )}
                    </div>
                </div>

                <button type="submit" className="btn btn-primary w-full">
                    Enregistrer
                </button>
            </form>
        </div>
    );
}