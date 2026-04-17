import fetchClient from "../lib/fetchClient";
import { PlayerWordDto } from "../types/impostorGameTypes";

export async function createSession(): Promise<{ code: string; id: string }> {
  return fetchClient.post("/ImpostorGame/create");
}

export async function joinSession(gameCode: string): Promise<{ id: number; sessionId: string }> {
  return fetchClient.post("/ImpostorGame/join", gameCode);
}

export async function startGame(sessionId: string): Promise<void> {
  await fetchClient.post(`/ImpostorGame/start/${sessionId}`);
}

export async function getMyWord(sessionId: string): Promise<PlayerWordDto> {
  return fetchClient.get(`/ImpostorGame/word/${sessionId}`);
}

export async function submitVote(sessionId: string, targetPlayerId: number): Promise<void> {
  await fetchClient.post(`/ImpostorGame/vote/${sessionId}`, { targetPlayerId });
}

export async function getSessionStatus(sessionId: string): Promise<{ status: number }> {
  return fetchClient.get(`/ImpostorGame/status/${sessionId}`);
}
