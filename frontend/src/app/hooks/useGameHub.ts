"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import * as signalR from "@microsoft/signalr";
import { GameStatus, Player, Clue } from "../types/impostorGameTypes";
import { tokenManager } from "../lib/fetchClient";

interface GameState {
  status: GameStatus;
  players: Player[];
  clues: Clue[];
  error: string | null;
  isConnected: boolean;
}

interface UseGameHubReturn {
  connection: signalR.HubConnection | null;
  gameState: GameState;
  joinGame: (gameCode: string) => Promise<void>;
  startGame: (gameCode: string) => Promise<void>;
  sendClue: (gameCode: string, clue: string) => Promise<void>;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
}

export function useGameHub(): UseGameHubReturn {
  const connectionRef = useRef<signalR.HubConnection | null>(null);
  const [gameState, setGameState] = useState<GameState>({
    status: GameStatus.Waiting,
    players: [],
    clues: [],
    error: null,
    isConnected: false,
  });

  const connect = useCallback(async () => {
    if (connectionRef.current?.state === signalR.HubConnectionState.Connected) {
      return;
    }

    const API_BASE = process.env.NEXT_PUBLIC_API_URL || "https://localhost:7001";
    
    const connection = new signalR.HubConnectionBuilder()
      .withUrl(`${API_BASE}/gamehub`, {
        withCredentials: true,
        accessTokenFactory: () => tokenManager.getToken() ?? "",
        transport: signalR.HttpTransportType.WebSockets | signalR.HttpTransportType.LongPolling,
      })
      .withAutomaticReconnect()
      .configureLogging(signalR.LogLevel.Warning)
      .build();

    connection.on("PlayerJoined", (data: { userId: string; playerId: number }) => {
      console.log("Player joined:", data);
      setGameState((prev) => ({
        ...prev,
        players: [...prev.players, { id: data.playerId, userId: data.userId, role: 0, isEliminated: false, hasVoted: false }],
      }));
    });

    connection.on("GameStarted", (data: { sessionId: string; playerCount: number }) => {
      console.log("Game started:", data);
      setGameState((prev) => ({
        ...prev,
        status: GameStatus.InProgress,
      }));
    });

    connection.on("ReceiveClue", (userId: string, clue: string) => {
      setGameState((prev) => ({
        ...prev,
        clues: [...prev.clues, { userId, userName: userId, clue, timestamp: new Date() }],
      }));
    });

    connection.on("Error", (message: string) => {
      setGameState((prev) => ({ ...prev, error: message }));
    });

    connection.onreconnecting(() => {
      setGameState((prev) => ({ ...prev, isConnected: false }));
    });

    connection.onreconnected(() => {
      setGameState((prev) => ({ ...prev, isConnected: true, error: null }));
    });

    connection.onclose(() => {
      setGameState((prev) => ({ ...prev, isConnected: false }));
    });

    try {
      await connection.start();
      connectionRef.current = connection;
      setGameState((prev) => ({ ...prev, isConnected: true }));
    } catch (err) {
      setGameState((prev) => ({ ...prev, error: "Failed to connect to game server" }));
      throw err;
    }
  }, []);

  const disconnect = useCallback(async () => {
    if (connectionRef.current) {
      await connectionRef.current.stop();
      connectionRef.current = null;
      setGameState({
        status: GameStatus.Waiting,
        players: [],
        clues: [],
        error: null,
        isConnected: false,
      });
    }
  }, []);

  const joinGame = useCallback(async (gameCode: string) => {
    if (!connectionRef.current) {
      throw new Error("Not connected to game hub");
    }
    await connectionRef.current.invoke("JoinGame", gameCode);
  }, []);

  const startGame = useCallback(async (gameCode: string) => {
    if (!connectionRef.current) {
      throw new Error("Not connected to game hub");
    }
    await connectionRef.current.invoke("StartGame", gameCode);
  }, []);

  const sendClue = useCallback(async (gameCode: string, clue: string) => {
    if (!connectionRef.current) {
      throw new Error("Not connected to game hub");
    }
    await connectionRef.current.invoke("SendClue", gameCode, clue);
  }, []);

  useEffect(() => {
    return () => {
      disconnect();
    };
  }, [disconnect]);

  return {
    connection: connectionRef.current,
    gameState,
    joinGame,
    startGame,
    sendClue,
    connect,
    disconnect,
  };
}
