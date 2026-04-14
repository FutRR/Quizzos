using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using MonAPIDotNet.Service;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace MonAPIDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class QuizAttemptController : ControllerBase
    {
        private readonly IQuizAttemptService _quizAttemptService;
        private readonly UserManager<ApplicationUser> _userManager;

        public QuizAttemptController(IQuizAttemptService quizAttemptService, UserManager<ApplicationUser> userManager)
        {
            _quizAttemptService = quizAttemptService;
            _userManager = userManager;
        }

        // POST /api/quizattempt/submit

        /// <summary>
        /// Soumet les réponses d'un quiz et retourne le résultat calculé côté serveur.
        /// </summary>
        /// <param name="dto">Les réponses sélectionnées par l'utilisateur.</param>
        /// <returns>Le résultat détaillé de la tentative.</returns>
        /// <response code="200">Le résultat de la tentative avec score et détail par question.</response>
        /// <response code="401">Non autorisé. L'utilisateur doit être authentifié.</response>
        /// <response code="404">Non trouvé. Le quiz n'existe pas.</response>
        [Authorize]
        [HttpPost("submit")]
        [ProducesResponseType(typeof(QuizAttemptResultDTO), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<QuizAttemptResultDTO>> SubmitQuiz([FromBody] SubmitQuizDTO dto)
        {
            var userId = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var result = await _quizAttemptService.SubmitQuizAsync(userId, dto);
            return Ok(result);
        }

        // GET /api/quizattempt/stats/{username}

        /// <summary>
        /// Récupère les statistiques de quiz d'un utilisateur via son nom d'utilisateur.
        /// </summary>
        /// <param name="username">Le nom d'utilisateur.</param>
        /// <returns>Les statistiques de l'utilisateur.</returns>
        /// <response code="200">Les statistiques de l'utilisateur.</response>
        /// <response code="404">Utilisateur introuvable.</response>
        [HttpGet("stats/{username}")]
        [ProducesResponseType(typeof(UserStatsDTO), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<UserStatsDTO>> GetUserStats(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
                return NotFound("User not found.");

            var stats = await _quizAttemptService.GetUserStatsAsync(user.Id);
            return Ok(stats);
        }
    }
}
