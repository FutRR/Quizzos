"use client";

import { useState, useRef } from "react";
import questionService from "@/app/services/questionService";
import fetchClient from "@/app/lib/fetchClient";
import MultipleChoiceAnswers from "./Answers/MultipleChoiceAnswers";
import TrueFalseAnswers from "./Answers/TrueFalseAnswers";
import ShortAnswerInput from "./Answers/ShortAnswerInput";

interface Answer {
  value: string;
  isCorrect: boolean;
}

interface CreateQuestionProps {
  quizId: string;
  onQuestionCreated?: () => void;
}

export default function CreateQuestion({ quizId, onQuestionCreated }: CreateQuestionProps) {
  const [text, setText] = useState("");
  const [type, setType] = useState("MultipleChoice");

  const handleTypeChange = (newType: string) => {
    setType(newType);
    if (newType === "TrueFalse") {
      setAnswers([
        { value: "Vrai", isCorrect: true },
        { value: "Faux", isCorrect: false },
      ]);
    } else if (newType === "ShortAnswer") {
      setAnswers([{ value: "", isCorrect: true }]);
    } else {
      setAnswers([
        { value: "", isCorrect: false },
        { value: "", isCorrect: false },
      ]);
    }
  };

  const [isTimed, setIsTimed] = useState(false);
  const [timeLimit, setTimeLimit] = useState<number>(30);
  const [answers, setAnswers] = useState<Answer[]>([
    { value: "", isCorrect: false },
    { value: "", isCorrect: false },
  ]);
  const [imagesUrls, setImagesUrls] = useState<string[]>([]);
  const [uploading, setUploading] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      setError("Le fichier doit faire moins de 5MB");
      return;
    }

    setUploading(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const data = await fetchClient.postFormData<{ imageUrl: string }>("/Upload/image", formData);
      setImagesUrls([...imagesUrls, data.imageUrl]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erreur lors de l'upload");
    } finally {
      setUploading(false);
    }
  };

  const handleRemoveImage = (index: number) => {
    setImagesUrls(imagesUrls.filter((_, i) => i !== index));
  };

  const handleSubmit = async () => {
    setError(null);
    setSuccess(false);

    if (!text.trim()) {
      setError("Veuillez entrer le texte de la question");
      return;
    }

    const filledAnswers = answers.filter((a) => a.value.trim());
    if (type === "ShortAnswer") {
      if (filledAnswers.length < 1) {
        setError("Veuillez entrer la réponse attendue");
        return;
      }
    } else {
      if (filledAnswers.length < 2) {
        setError("Veuillez entrer au moins 2 réponses");
        return;
      }
      if (!filledAnswers.some((a) => a.isCorrect)) {
        setError("Veuillez sélectionner au moins une bonne réponse");
        return;
      }
    }

    setLoading(true);
    try {
      await questionService.createQuestion(quizId, {
        text: text.trim(),
        type,
        isTimed,
        timeLimit: isTimed ? timeLimit : undefined,
        imagesUrls,
        answers: filledAnswers,
      });
      setSuccess(true);
      // Reset form
      setText("");
      if (type === "TrueFalse") {
        setAnswers([
          { value: "Vrai", isCorrect: true },
          { value: "Faux", isCorrect: false },
        ]);
      } else if (type === "ShortAnswer") {
        setAnswers([{ value: "", isCorrect: true }]);
      } else {
        setAnswers([
          { value: "", isCorrect: false },
          { value: "", isCorrect: false },
        ]);
      }
      setImagesUrls([]);
      setIsTimed(false);
      setTimeLimit(30);
      onQuestionCreated?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erreur lors de la création");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto mt-10">
      {error && (
        <div className="bg-red-500/20 border border-red-500/50 text-red-300 px-4 py-2 rounded-lg mb-4 text-sm">
          {error}
        </div>
      )}
      {success && (
        <div className="bg-green-500/20 border border-green-500/50 text-green-300 px-4 py-2 rounded-lg mb-4 text-sm">
          Question ajoutée avec succès !
        </div>
      )}

      {/* Question text */}
      <div className="space-y-4 bg-gray-800 p-8 rounded-lg w-full mx-auto border border-gray-700">
        <h2 className="text-lg font-bold text-center text-white">
          Ajoutez Votre Question
        </h2>
        <input
          type="text"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Tapez votre question ici..."
          className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:border-indigo-500 transition-colors"
        />
        <div className="flex flex-wrap gap-4 items-center justify-center">
          <select
            value={type}
            onChange={(e) => handleTypeChange(e.target.value)}
            className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-indigo-500"
          >
            <option value="MultipleChoice">Choix multiple</option>
            <option value="TrueFalse">Vrai / Faux</option>
            <option value="ShortAnswer">Réponse courte</option>
          </select>
          <label className="flex items-center gap-2 text-white text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={isTimed}
              onChange={(e) => setIsTimed(e.target.checked)}
              className="w-4 h-4 rounded"
            />
            Chronométré
          </label>
          {isTimed && (
            <div className="flex items-center gap-2">
              <input
                type="number"
                value={timeLimit}
                onChange={(e) => setTimeLimit(Number(e.target.value))}
                min={5}
                max={300}
                className="w-20 bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-indigo-500"
              />
              <span className="text-gray-400 text-sm">sec</span>
            </div>
          )}
        </div>
      </div>

      {/* Media upload */}
      <div className="space-y-4 bg-gray-800 p-8 rounded-lg w-full mx-auto mt-2 border border-gray-700">
        <h2 className="text-lg font-bold text-center text-white mt-2">
          Ajoutez un multimedia
        </h2>
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          onChange={handleImageUpload}
          className="hidden"
        />
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          disabled={uploading}
          className="block mx-auto"
        >
          <img
            className={`w-12 h-12 mx-auto ${uploading ? "opacity-50 animate-pulse" : "hover:opacity-80"} transition-opacity`}
            src="/icons/Plus.svg"
            alt="Ajouter un multimedia"
          />
        </button>
        <p className="text-sm text-center text-white">
          {uploading ? "Upload en cours..." : "(.JPG, .PNG, .MP4, .MP3, .GIF)"}
        </p>
      </div>

      {/* Answers — dynamic per type */}
      {type === "MultipleChoice" && (
        <MultipleChoiceAnswers answers={answers} onAnswersChange={setAnswers} />
      )}
      {type === "TrueFalse" && (
        <TrueFalseAnswers answers={answers} onAnswersChange={setAnswers} />
      )}
      {type === "ShortAnswer" && (
        <ShortAnswerInput answers={answers} onAnswersChange={setAnswers} />
      )}

      {/* Images carousel */}
      {imagesUrls.length > 0 && (
        <div className="flex overflow-x-auto flex-nowrap bg-gray-800 p-2 rounded-lg border border-gray-700 mt-4 gap-2">
          {imagesUrls.map((url, index) => (
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
                onClick={() => handleRemoveImage(index)}
                className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity"
              >
                <span className="text-red-400 text-lg">✕</span>
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Submit */}
      <button
        type="button"
        onClick={handleSubmit}
        disabled={loading}
        className="w-full mt-4 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold py-3 rounded-lg transition-colors"
      >
        {loading ? "Création..." : "Ajouter la question"}
      </button>
    </div>
  );
}