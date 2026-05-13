export interface RoundDto { roundId: string; imageId: string; }
export interface GuessResultDto {
  distanceKm: number;
  score: number;
  actualLat: number;
  actualLng: number;
}
export type GeoPhase = "idle" | "playing" | "result" | "finished";
export interface GeoGameState {
  rounds: { round: RoundDto; result?: GuessResultDto }[];
  currentIndex: number;
  totalScore: number;
  phase: GeoPhase;
}