using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;
using MonAPIDotNet.Service;
using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using System.IdentityModel.Tokens.Jwt;

namespace MonAPIDotNet.Hubs
{
    [Authorize]
    public class GameHub : Hub
    {
        private readonly IImpostorGameService _gameService;

        public GameHub(IImpostorGameService gameService)
        {
            _gameService = gameService;
        }

        public async Task JoinGame(string gameCode)
        {
            var userId = Context.User?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                throw new HubException("User not authenticated.");
            }

            // Vérifier d'abord que la session existe et accepte des joueurs
            var session = await _gameService.GetSessionByCodeAsync(gameCode);
            if (session == null || session.Status != GameStatus.Waiting)
            {
                await Clients.Caller.SendAsync("Error", "Session not found or not accepting players.");
                return;
            }

            try
            {
                var player = await _gameService.JoinSessionAsync(gameCode, userId);
                if (player == null)
                {
                    await Clients.Caller.SendAsync("Error", "Failed to join session.");
                    return;
                }

                await Groups.AddToGroupAsync(Context.ConnectionId, gameCode);

                // Reload session to get an up-to-date players list (incl. the one we just added)
                var refreshed = await _gameService.GetSessionByCodeAsync(gameCode);
                var snapshot = refreshed?.Players
                    .Select(p => new { id = p.Id, userId = p.UserId, role = (int)p.Role, isEliminated = p.IsEliminated, hasVoted = p.HasVoted })
                    .ToList();

                // Send full snapshot to the caller so it knows about already-present players
                await Clients.Caller.SendAsync("PlayersSync", snapshot);

                // Notify everyone (including the caller) that a new player joined
                await Clients.Group(gameCode).SendAsync("PlayerJoined", new { userId, playerId = player.Id });
            }
            catch (Exception ex)
            {
                await Clients.Caller.SendAsync("Error", ex.Message);
            }
        }

        public async Task SendClue(string gameCode, string clue)
        {
            var userId = Context.User?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            await Clients.Group(gameCode).SendAsync("ReceiveClue", userId, clue);
        }

        public async Task StartGame(string gameCode)
        {
            var userId = Context.User?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                throw new HubException("User not authenticated.");
            }

            var session = await _gameService.GetSessionByCodeAsync(gameCode);
            if (session == null)
            {
                await Clients.Caller.SendAsync("Error", "Session not found.");
                return;
            }

            // Vérifier que la partie peut être démarrée (minimum 3 joueurs)
            if (session.Players.Count < 3)
            {
                await Clients.Caller.SendAsync("Error", "Not enough players. Minimum 3 required.");
                return;
            }

            // Démarrer la partie via le service
            var started = await _gameService.StartGameAsync(session.Id);
            if (!started)
            {
                await Clients.Caller.SendAsync("Error", "Failed to start game.");
                return;
            }

            // Notifier tous les joueurs que la partie a commencé
            await Clients.Group(gameCode).SendAsync("GameStarted", new
            {
                sessionId = session.Id,
                playerCount = session.Players.Count
            });
        }
    }
}
