export enum PlayerRole {
  Civilian = 0,
  Impostor = 1,
}

export enum GameStatus {
  Waiting = 0,
  InProgress = 1,
  Finished = 2,
}

export enum WinnerType {
  None = 0,
  Civilians = 1,
  Impostor = 2,
}

export interface PlayerWordDto {
  role: PlayerRole;
  word: string;
}

export interface VoteSubmissionDto {
  targetPlayerId: number;
}

export interface GameSessionInfoDto {
  id: string;
  code: string;
  status: GameStatus;
  playerCount: number;
}

export interface Player {
  id: number;
  userId: string;
  role: PlayerRole;
  isEliminated: boolean;
  hasVoted: boolean;
  userName?: string;
}

export interface GameSession {
  id: string;
  code: string;
  status: GameStatus;
  players: Player[];
  winner: WinnerType;
}

export interface Clue {
  userId: string;
  userName: string;
  clue: string;
  timestamp: Date;
}
