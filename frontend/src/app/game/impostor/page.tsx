"use client";

import { useState, useEffect, useCallback } from "react";
import { GameLobby } from "../../components/ImpostorGame/GameLobby";
import { WaitingRoom } from "../../components/ImpostorGame/WaitingRoom";
import { GameBoard } from "../../components/ImpostorGame/GameBoard";
import { useGameHub } from "../../hooks/useGameHub";
import { useAuth } from "../../hooks/useAuth";
import { getMyWord } from "../../services/impostorGameService";
import { PlayerWordDto, GameStatus } from "../../types/impostorGameTypes";
import { useRouter } from "next/navigation";

export default function ImpostorGamePage() {
  const [gameState, setGameState] = useState<{
    sessionId: string | null;
    gameCode: string | null;
    playerId: number | null;
    currentUserId: string;
    phase: "lobby" | "waiting" | "playing" | "voting" | "finished";
    playerInfo: PlayerWordDto | null;
  }>({
    sessionId: null,
    gameCode: null,
    playerId: null,
    currentUserId: "",
    phase: "lobby",
    playerInfo: null,
  });

  const { connect, disconnect, joinGame, startGame, sendClue, gameState: hubState } = useGameHub();
  const { user, loading: authLoading } = useAuth();
  const router = useRouter();

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!authLoading && !user) {
      router.push("/login");
    }
  }, [authLoading, user, router]);

  // Connect to hub once auth is ready
  useEffect(() => {
    if (authLoading || !user) return;
    connect();
    return () => {
      disconnect();
    };
  }, [authLoading, user, connect, disconnect]);

  // Handle game status changes from hub
  useEffect(() => {
    if (hubState.status === GameStatus.InProgress && gameState.phase === "waiting") {
      // Game started, fetch player word
      handleGameStarted();
    }
  }, [hubState.status, gameState.phase]);

  const handleJoined = async (sessionId: string, gameCode: string, playerId: number) => {
    setGameState((prev) => ({
      ...prev,
      sessionId,
      gameCode,
      playerId,
      phase: "waiting",
    }));

    try {
      await joinGame(gameCode);
    } catch (err) {
      console.error("Failed to join game hub:", err);
    }
  };

  const handleGameStarted = async () => {
    if (!gameState.sessionId) return;
    
    try {
      const playerInfo = await getMyWord(gameState.sessionId);
      setGameState((prev) => ({
        ...prev,
        playerInfo,
        phase: "playing",
      }));
    } catch (err) {
      console.error("Failed to get player word:", err);
    }
  };

  const handleStartGame = async () => {
    if (!gameState.gameCode) return;
    
    try {
      await startGame(gameState.gameCode);
    } catch (err) {
      console.error("Failed to start game:", err);
    }
  };

  const handleSendClue = async (clue: string) => {
    if (!gameState.gameCode) return;
    
    try {
      await sendClue(gameState.gameCode, clue);
    } catch (err) {
      console.error("Failed to send clue:", err);
    }
  };

  // Error display
  if (hubState.error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="p-6 bg-red-100 text-red-700 rounded-lg">
          Error: {hubState.error}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen py-8 px-4">
      <div className="max-w-4xl mx-auto">
        {/* Game phases */}
        {gameState.phase === "lobby" && (
          <GameLobby onJoined={handleJoined} />
        )}

        {gameState.phase === "waiting" && gameState.sessionId && gameState.gameCode && (
          <WaitingRoom
            gameCode={gameState.gameCode}
            sessionId={gameState.sessionId}
            players={hubState.players}
            currentUserId={gameState.currentUserId}
            onGameStarted={() => {}} // Handled by hub state change
          />
        )}

        {gameState.phase === "playing" && gameState.playerInfo && gameState.gameCode && (
          <GameBoard
            gameCode={gameState.gameCode}
            playerInfo={gameState.playerInfo}
            clues={hubState.clues}
            players={hubState.players}
            currentUserId={gameState.currentUserId}
            onSendClue={handleSendClue}
          />
        )}

        {gameState.phase === "voting" && (
          <div className="text-center p-8">
            <h2 className="text-2xl font-bold">Voting Phase</h2>
            <p className="text-gray-600 mt-2">Vote for who you think is the impostor!</p>
          </div>
        )}

        {gameState.phase === "finished" && (
          <div className="text-center p-8">
            <h2 className="text-2xl font-bold">Game Over!</h2>
            <p className="text-gray-600 mt-2">
              {hubState.players.find(p => p.role === 1 && !p.isEliminated) 
                ? "The Impostor won!" 
                : "The Civilians won!"}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
