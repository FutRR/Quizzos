using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;

namespace MonAPIDotNet.Service
{
    public interface IImpostorGameService
    {
        Task<ImpostorGameSession> CreateSessionAsync();
        Task<ImpostorPlayer> JoinSessionAsync(string gameCode, string userId);
        Task<bool> StartGameAsync(Guid sessionId);
        Task<PlayerWordDto?> GetPlayerWordAsync(Guid sessionId, string userId);
        Task<bool> SubmitVoteAsync(Guid sessionId, string voterId, int targetPlayerId);
        Task<GameStatus> GetSessionStatusAsync(Guid sessionId);
        Task<ImpostorGameSession?> GetSessionByCodeAsync(string gameCode);
    }
}
