"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../hooks/useAuth";
import { startRound, submitGuess } from "../../services/geoGameService";
import { GeoGameState } from "../../types/geoGameTypes";
import dynamic from "next/dynamic";

const ROUNDS_PER_GAME = 5;

const StreetView = dynamic(
  () => import("../../components/GeoGame/StreetView").then(m => m.StreetView),
  { ssr: false, loading: () => <div className="h-[70vh] bg-zinc-200 animate-pulse rounded-lg" /> }
);
const GuessMap = dynamic(
  () => import("../../components/GeoGame/GuessMap").then(m => m.GuessMap),
  { ssr: false, loading: () => <div className="h-[50vh] bg-zinc-200 animate-pulse rounded-lg" /> }
);
const RoundResult = dynamic(
  () => import("../../components/GeoGame/RoundResult").then(m => m.RoundResult),
  { ssr: false }
);
const FinalScore = dynamic(
  () => import("../../components/GeoGame/FinalScore").then(m => m.FinalScore),
  { ssr: false }
);

export default function GeoGuessrPage() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const [lastGuess, setLastGuess] = useState<{ lat: number; lng: number } | null>(null);
  const [state, setState] = useState<GeoGameState>({
    rounds: [], currentIndex: 0, totalScore: 0, phase: "idle",
  });

  useEffect(() => {
    if (!loading && !user) router.push("/login");
  }, [loading, user, router]);

  async function handleStart() {
    const round = await startRound();
    setState({
      rounds: [{ round }],
      currentIndex: 0,
      totalScore: 0,
      phase: "playing",
    });
  }

  async function handleGuess(lat: number, lng: number) {
    setLastGuess({ lat, lng });
    const current = state.rounds[state.currentIndex];
    const result = await submitGuess(current.round.roundId, lat, lng);
    const rounds = [...state.rounds];
    rounds[state.currentIndex] = { ...current, result };
    setState(s => ({
      ...s,
      rounds,
      totalScore: s.totalScore + result.score,
      phase: "result",
    }));
  }

  async function handleNext() {
    if (state.currentIndex + 1 >= ROUNDS_PER_GAME) {
      setState(s => ({ ...s, phase: "finished" }));
      return;
    }
    const round = await startRound();
    setState(s => ({
      ...s,
      rounds: [...s.rounds, { round }],
      currentIndex: s.currentIndex + 1,
      phase: "playing",
    }));
  }

  const current = state.rounds[state.currentIndex];

  return (
    <div className="min-h-screen py-8 px-4 max-w-5xl mx-auto space-y-4">
      <header className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Geo Guess</h1>
        {state.phase !== "idle" && state.phase !== "finished" && (
          <span>Manche {state.currentIndex + 1} / {ROUNDS_PER_GAME} — Score : {state.totalScore}</span>
        )}
      </header>

      {state.phase === "idle" && (
        <button onClick={handleStart} className="px-6 py-3 bg-blue-600 text-white rounded text-lg">
          Commencer une partie
        </button>
      )}

      {state.phase === "playing" && current && (
        <div className="grid lg:grid-cols-2 gap-4">
          <StreetView imageId={current.round.imageId} />
          <GuessMap onSubmit={handleGuess} />
        </div>
      )}

      {state.phase === "result" && current?.result && (
        <RoundResult
          result={current.result}
          guessLat={lastGuess?.lat || 0}
          guessLng={lastGuess?.lng || 0}
          onNext={handleNext}
        />
      )}

      {state.phase === "finished" && (
        <FinalScore state={state} onRestart={handleStart} />
      )}
    </div>
  );
}