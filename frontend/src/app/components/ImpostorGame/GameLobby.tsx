"use client";

import { useState } from "react";
import { createSession, joinSession } from "../../services/impostorGameService";

interface GameLobbyProps {
  onJoined: (sessionId: string, gameCode: string, playerId: number) => void;
}

export function GameLobby({ onJoined }: GameLobbyProps) {
  const [gameCode, setGameCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreate = async () => {
    setLoading(true);
    setError(null);
    try {
      const session = await createSession();
      const player = await joinSession(session.code);
      onJoined(session.id, session.code, player.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create game");
    } finally {
      setLoading(false);
    }
  };

  const handleJoin = async () => {
    if (!gameCode.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const player = await joinSession(gameCode.toUpperCase());
      onJoined(player.sessionId, gameCode.toUpperCase(), player.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to join game");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-6 text-center">Impostor Game</h2>
      
      {error && (
        <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">
          {error}
        </div>
      )}

      <div className="space-y-4">
        <button
          onClick={handleCreate}
          disabled={loading}
          className="w-full py-3 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 font-medium"
        >
          {loading ? "Creating..." : "Create New Game"}
        </button>

        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <span className="w-full border-t border-gray-300" />
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white text-gray-500">Or join existing</span>
          </div>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Enter game code"
            value={gameCode}
            onChange={(e) => setGameCode(e.target.value.toUpperCase())}
            maxLength={6}
            className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent uppercase"
          />
          <button
            onClick={handleJoin}
            disabled={loading || !gameCode.trim()}
            className="px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 font-medium"
          >
            Join
          </button>
        </div>
      </div>
    </div>
  );
}
