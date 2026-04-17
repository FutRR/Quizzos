using Microsoft.AspNetCore.Mvc;
using MonAPIDotNet.Service;
using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace MonAPIDotNet.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ImpostorGameController : ControllerBase
    {
        private readonly IImpostorGameService _gameService;

        public ImpostorGameController(IImpostorGameService gameService)
        {
            _gameService = gameService;
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateSession()
        {
            var session = await _gameService.CreateSessionAsync();
            return Ok(new { session.Code, session.Id });
        }

        [HttpGet("status/{sessionId}")]
        public async Task<IActionResult> GetStatus(Guid sessionId)
        {
            var status = await _gameService.GetSessionStatusAsync(sessionId);
            return Ok(new { Status = status });
        }

        [HttpPost("join")]
        [Authorize]
        public async Task<IActionResult> Join([FromBody] string gameCode)
        {
            var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            try
            {
                var player = await _gameService.JoinSessionAsync(gameCode, userId);
                return Ok(new { player.Id, player.SessionId });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpPost("start/{sessionId}")]
        [Authorize]
        public async Task<IActionResult> StartGame(Guid sessionId)
        {
            var started = await _gameService.StartGameAsync(sessionId);
            if (!started)
                return BadRequest(new { error = "Failed to start game. Need at least 3 players." });

            return Ok(new { started = true });
        }

        [HttpPost("vote/{sessionId}")]
        [Authorize]
        public async Task<IActionResult> SubmitVote(Guid sessionId, [FromBody] VoteSubmissionDto vote)
        {
            var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var result = await _gameService.SubmitVoteAsync(sessionId, userId, vote.TargetPlayerId);
            if (!result)
                return BadRequest(new { error = "Failed to submit vote." });

            return Ok(new { submitted = true });
        }

        [HttpGet("word/{sessionId}")]
        [Authorize]
        public async Task<IActionResult> GetMyWord(Guid sessionId)
        {
            var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var playerInfo = await _gameService.GetPlayerWordAsync(sessionId, userId);
            if (playerInfo == null)
                return NotFound(new { error = "Player not found or eliminated." });

            return Ok(playerInfo);
        }
    }
}
