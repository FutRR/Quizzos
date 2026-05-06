"use client";

import { Player } from "../../types/impostorGameTypes";

interface WaitingRoomProps {
  gameCode: string;
  sessionId: string;
  players: Player[];
  currentUserId: string;
  onStartGame: () => Promise<void> | void;
}

export function WaitingRoom({ gameCode, sessionId, players, currentUserId, onStartGame }: WaitingRoomProps) {
  const canStart = players.length >= 3;

  const handleStart = async () => {
    if (!canStart) return;
    try {
      await onStartGame();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to start game");
    }
  };

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-md text-gray-900">
      <div className="text-center mb-6">
        <h2 className="text-2xl font-bold">Waiting Room</h2>
        <div className="mt-2 text-4xl font-mono font-bold text-blue-600 tracking-wider">
          {gameCode}
        </div>
        <p className="text-gray-500 mt-1">Share this code with friends</p>
      </div>

      <div className="mb-6">
        <h3 className="text-lg font-semibold mb-3">
          Players ({players.length})
        </h3>
        <div className="space-y-2">
          {players.map((player) => (
            <div
              key={player.id}
              className={`p-3 rounded-lg border ${
                player.userId === currentUserId
                  ? "bg-blue-50 border-blue-300"
                  : "bg-gray-50 border-gray-200"
              }`}
            >
              <span className="font-medium">
                {player.userId === currentUserId ? "You" : `Player ${player.id}`}
              </span>
              {player.userId === currentUserId && (
                <span className="ml-2 text-xs bg-blue-200 text-blue-800 px-2 py-1 rounded">
                  You
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="space-y-3">
        <button
          onClick={handleStart}
          disabled={!canStart}
          className="w-full py-3 px-4 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
        >
          {canStart ? "Start Game" : `Need ${3 - players.length} more player(s)`}
        </button>
        
        {!canStart && (
          <p className="text-center text-sm text-gray-500">
            Minimum 3 players required to start
          </p>
        )}
      </div>
    </div>
  );
}
