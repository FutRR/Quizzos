"use client";
import { GeoGameState } from "../../types/geoGameTypes";

export function FinalScore({ state, onRestart }: { state: GeoGameState; onRestart: () => void }) {
  return (
    <div className="text-center p-8 space-y-4">
      <h2 className="text-3xl font-bold">Partie terminée !</h2>
      <p className="text-2xl">Score total : <b>{state.totalScore}</b> / {state.rounds.length * 5000}</p>
      <ul className="text-left max-w-md mx-auto">
        {state.rounds.map((r, i) => (
          <li key={i} className="flex justify-between border-b py-1">
            <span>Manche {i + 1}</span>
            <span>{r.result?.score ?? 0} pts ({r.result?.distanceKm.toFixed(0) ?? "-"} km)</span>
          </li>
        ))}
      </ul>
      <button onClick={onRestart} className="px-4 py-2 bg-blue-600 text-white rounded">
        Rejouer
      </button>
    </div>
  );
}