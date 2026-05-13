import fetchClient from "../lib/fetchClient";
import { RoundDto, GuessResultDto } from "../types/geoGameTypes";

export async function startRound(): Promise<RoundDto> {
  return fetchClient.post("/geogame/round", undefined, { timeout: 30000 });
}

export async function submitGuess(
  roundId: string, lat: number, lng: number,
): Promise<GuessResultDto> {
  return fetchClient.post("/geogame/guess", { roundId, lat, lng }, { timeout: 15000 });
}