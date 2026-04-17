using Microsoft.EntityFrameworkCore;
using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;

namespace MonAPIDotNet.Service
{
    public class ImpostorGameService : IImpostorGameService
    {
        private readonly MyDbContext _context;

        public ImpostorGameService(MyDbContext context)
        {
            _context = context;
        }

        public async Task<ImpostorGameSession> CreateSessionAsync()
        {
            var session = new ImpostorGameSession
            {
                Code = GenerateGameCode(),
                Status = GameStatus.Waiting
            };

            _context.ImpostorGameSessions.Add(session);
            await _context.SaveChangesAsync();
            return session;
        }

        public async Task<ImpostorPlayer> JoinSessionAsync(string gameCode, string userId)
        {
            var session = await _context.ImpostorGameSessions
                .FirstOrDefaultAsync(s => s.Code == gameCode && s.Status == GameStatus.Waiting);

            if (session == null) throw new Exception("Session not found or not accepting players.");

            var existingPlayer = await _context.ImpostorPlayers
                .FirstOrDefaultAsync(p => p.SessionId == session.Id && p.UserId == userId);

            if (existingPlayer != null) return existingPlayer;

            var player = new ImpostorPlayer
            {
                SessionId = session.Id,
                UserId = userId,
                Role = PlayerRole.Civilian // Role is assigned when game starts
            };

            _context.ImpostorPlayers.Add(player);
            await _context.SaveChangesAsync();
            return player;
        }

        public async Task<bool> StartGameAsync(Guid sessionId)
        {
            var session = await _context.ImpostorGameSessions
                .Include(s => s.Players)
                .FirstOrDefaultAsync(s => s.Id == sessionId);

            if (session == null || session.Players.Count < 3) return false;

            // 1. Pick a random word pair
            var wordPair = await _context.ImpostorWordPairs
                .OrderBy(r => Guid.NewGuid())
                .FirstOrDefaultAsync();

            if (wordPair == null) throw new Exception("No word pairs available in database.");

            session.SecretWord = wordPair.WordA;
            session.ImpostorWord = wordPair.WordB;
            session.Status = GameStatus.InProgress;

            // 2. Assign roles (1 Impostor, others Civilians)
            var players = session.Players.ToList();
            var impostorIndex = Random.Shared.Next(players.Count);

            for (int i = 0; i < players.Count; i++)
            {
                players[i].Role = (i == impostorIndex) ? PlayerRole.Impostor : PlayerRole.Civilian;
            }

            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<PlayerWordDto?> GetPlayerWordAsync(Guid sessionId, string userId)
        {
            var player = await _context.ImpostorPlayers
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.SessionId == sessionId && p.UserId == userId);

            if (player == null || player.IsEliminated) return null;

            var session = await _context.ImpostorGameSessions
                .AsNoTracking()
                .FirstOrDefaultAsync(s => s.Id == sessionId);

            if (session == null || session.Status != GameStatus.InProgress) return null;

            return new PlayerWordDto
            {
                Role = player.Role,
                Word = player.Role == PlayerRole.Impostor ? session.ImpostorWord! : session.SecretWord!
            };
        }

        public async Task<bool> SubmitVoteAsync(Guid sessionId, string voterId, int targetPlayerId)
        {
            var session = await _context.ImpostorGameSessions
                .Include(s => s.Players)
                .FirstOrDefaultAsync(s => s.Id == sessionId && s.Status == GameStatus.InProgress);

            if (session == null) return false;

            var voter = session.Players.FirstOrDefault(p => p.UserId == voterId && !p.IsEliminated);
            var target = session.Players.FirstOrDefault(p => p.Id == targetPlayerId && !p.IsEliminated);

            if (voter == null || target == null || voter.IsEliminated) return false;

            if (voter.HasVoted) return false;

            voter.HasVoted = true;
            voter.VotedForPlayerId = targetPlayerId;

            // Vérifier si tous les joueurs actifs ont voté
            var activePlayers = session.Players.Where(p => !p.IsEliminated).ToList();
            var allVoted = activePlayers.All(p => p.HasVoted);

            if (allVoted)
            {
                // Compter les votes et éliminer
                var voteCounts = activePlayers
                    .Where(p => p.VotedForPlayerId.HasValue)
                    .GroupBy(p => p.VotedForPlayerId!.Value)
                    .ToDictionary(g => g.Key, g => g.Count());

                var maxVotes = voteCounts.Values.Any() ? voteCounts.Values.Max() : 0;
                var eliminatedPlayerIds = voteCounts
                    .Where(v => v.Value == maxVotes)
                    .Select(v => v.Key)
                    .ToList();

                // En cas d'égalité, on élimine personne (ou on pourrait faire un autre tour)
                if (eliminatedPlayerIds.Count == 1)
                {
                    var eliminated = session.Players.FirstOrDefault(p => p.Id == eliminatedPlayerIds[0]);
                    if (eliminated != null)
                    {
                        eliminated.IsEliminated = true;
                        eliminated.EliminatedAt = DateTime.UtcNow;
                    }
                }

                // Réinitialiser les votes pour le prochain tour
                foreach (var p in activePlayers)
                {
                    p.HasVoted = false;
                    p.VotedForPlayerId = null;
                }

                // Vérifier la fin de partie
                await CheckGameEndAsync(session);
            }

            await _context.SaveChangesAsync();
            return true;
        }

        private async Task CheckGameEndAsync(ImpostorGameSession session)
        {
            var activePlayers = session.Players.Where(p => !p.IsEliminated).ToList();
            var impostor = activePlayers.FirstOrDefault(p => p.Role == PlayerRole.Impostor);
            var civilians = activePlayers.Where(p => p.Role == PlayerRole.Civilian).ToList();

            // L'imposteur gagne s'il reste autant d'imposteur que de civils
            // Ou si tous les civils sont éliminés
            if (impostor == null || impostor.IsEliminated)
            {
                session.Status = GameStatus.Finished;
                session.Winner = WinnerType.Civilians;
            }
            else if (civilians.Count <= 1)
            {
                session.Status = GameStatus.Finished;
                session.Winner = WinnerType.Impostor;
            }

            await _context.SaveChangesAsync();
        }

        public async Task<GameStatus> GetSessionStatusAsync(Guid sessionId)
        {
            var session = await _context.ImpostorGameSessions
                .FirstOrDefaultAsync(s => s.Id == sessionId);
            return session?.Status ?? GameStatus.Finished;
        }

        public async Task<ImpostorGameSession?> GetSessionByCodeAsync(string gameCode)
        {
            return await _context.ImpostorGameSessions
                .Include(s => s.Players)
                .FirstOrDefaultAsync(s => s.Code == gameCode);
        }

        private string GenerateGameCode()
        {
            return Guid.NewGuid().ToString("N").Substring(0, 6).ToUpper();
        }
    }
}
