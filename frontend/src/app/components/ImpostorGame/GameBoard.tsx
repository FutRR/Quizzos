"use client";

import { useState } from "react";
import { PlayerWordDto, PlayerRole, Clue, Player } from "../../types/impostorGameTypes";

interface GameBoardProps {
  gameCode: string;
  playerInfo: PlayerWordDto;
  clues: Clue[];
  players: Player[];
  currentUserId: string;
  onSendClue: (clue: string) => void;
}

export function GameBoard({ gameCode, playerInfo, clues, players, currentUserId, onSendClue }: GameBoardProps) {
  const [clue, setClue] = useState("");
  const isImpostor = playerInfo.role === PlayerRole.Impostor;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!clue.trim()) return;
    onSendClue(clue.trim());
    setClue("");
  };

  return (
    <div className="max-w-2xl mx-auto p-6">
      {/* Word Card */}
      <div className={`mb-6 p-6 rounded-lg text-center ${
        isImpostor 
          ? "bg-red-100 border-2 border-red-500" 
          : "bg-green-100 border-2 border-green-500"
      }`}>
        <div className="text-sm uppercase tracking-wide text-gray-600 mb-2">
          Your Role
        </div>
        <div className={`text-2xl font-bold mb-4 ${
          isImpostor ? "text-red-700" : "text-green-700"
        }`}>
          {isImpostor ? "🕵️ IMPOSTOR" : "👤 CIVILIAN"}
        </div>
        <div className="text-sm text-gray-600 mb-2">Your Word</div>
        <div className="text-4xl font-bold text-gray-800">
          {playerInfo.word}
        </div>
        {isImpostor && (
          <p className="mt-4 text-red-600 text-sm">
            ⚠️ Try to blend in! Don't get caught!
          </p>
        )}
      </div>

      {/* Active Players */}
      <div className="mb-6 p-4 bg-white rounded-lg shadow">
        <h3 className="font-semibold mb-3">Active Players</h3>
        <div className="flex flex-wrap gap-2">
          {players.filter(p => !p.isEliminated).map((player) => (
            <span
              key={player.id}
              className={`px-3 py-1 rounded-full text-sm ${
                player.userId === currentUserId
                  ? "bg-blue-200 text-blue-800"
                  : "bg-gray-200 text-gray-700"
              }`}
            >
              {player.userId === currentUserId ? "You" : `Player ${player.id}`}
            </span>
          ))}
        </div>
      </div>

      {/* Clue Input */}
      <form onSubmit={handleSubmit} className="mb-6">
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Give a clue about the word..."
            value={clue}
            onChange={(e) => setClue(e.target.value)}
            maxLength={100}
            className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
          />
          <button
            type="submit"
            disabled={!clue.trim()}
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            Send
          </button>
        </div>
      </form>

      {/* Clue History */}
      <div className="bg-white rounded-lg shadow">
        <h3 className="font-semibold p-4 border-b">Clues</h3>
        <div className="divide-y">
          {clues.length === 0 ? (
            <p className="p-4 text-gray-500 text-center">No clues yet. Be the first!</p>
          ) : (
            clues.map((c, index) => (
              <div key={index} className="p-4">
                <div className="flex justify-between items-start mb-1">
                  <span className="font-medium text-sm text-gray-700">
                    {c.userId === currentUserId ? "You" : `Player ${index + 1}`}
                  </span>
                  <span className="text-xs text-gray-400">
                    {c.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </span>
                </div>
                <p className="text-gray-800">{c.clue}</p>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
