using MonAPIDotNet.DTOs;
using MonAPIDotNet.Service;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;

namespace MonAPIDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class QuizController : ControllerBase
    {
        private readonly IQuizService _quizService;

        public QuizController(IQuizService quizService)
        {
            _quizService = quizService;
        }

        // GET /api/quiz/quiz

        /// <summary>
        /// Récupère la liste de tous les quiz avec leurs questions, réponses, images et tags.
        /// </summary>
        /// <param name="page">Le numéro de page (optionnel, par défaut à 1).</param>
        /// <param name="pageSize">Le nombre de quiz par page (optionnel, par défaut à 20, maximum 100).</param>
        /// <returns>La liste de tous les quiz avec leurs questions, réponses, images et tags.</returns>
        /// <response code="200">La liste de tous les quiz avec leurs questions, réponses, images et tags.</response>
        [HttpGet("quizzes")]
        [ProducesResponseType(typeof(List<QuizDTO>), StatusCodes.Status200OK)]
        public async Task<ActionResult<List<QuizDTO>>> GetAllQuizzesAsync(int page = 1, int pageSize = 20)
        {
            var quizzes = await _quizService.GetAllQuizzesAsync(page, pageSize);
            return Ok(quizzes);
        }

        // GET /api/quiz/search

        /// <summary>
        /// Recherche des quiz par mot-clé, avec pagination.
        /// </summary>
        /// <param name="query">Le mot-clé de recherche.</param>
        /// <param name="page">Le numéro de page (optionnel, par défaut à 1).</param>
        /// <param name="pageSize">Le nombre de quiz par page (optionnel, par défaut à 20, maximum 100).</param>
        /// <returns>La liste des quiz correspondant à la recherche, avec leurs questions, réponses, images et tags.</returns>
        /// <response code="200">La liste des quiz correspondant à la recherche, avec leurs questions, réponses, images et tags.</response>
        [HttpGet("search")]
        [ProducesResponseType(typeof(List<QuizDTO>), StatusCodes.Status200OK)]
        public async Task<ActionResult<List<QuizDTO>>> SearchQuizzesAsync(string query, int page = 1, int pageSize = 20)
        {
            var quizzes = await _quizService.SearchQuizzesAsync(query, page, pageSize);
            return Ok(quizzes);
        }

        // GET /api/quiz/{id}

        /// <summary>
        /// Récupère un quiz par son ID, avec ses questions, réponses, images et tags.
        /// </summary>
        /// <param name="id">L'ID du quiz à récupérer.</param>
        /// <returns>Le quiz correspondant à l'ID fourni, avec ses questions, réponses, images et tags.</returns>
        /// <response code="200">Le quiz correspondant à l'ID fourni, avec ses questions, réponses, images et tags.</response>
        /// <response code="404">Non trouvé. Aucun quiz ne correspond à l'ID fourni.</response>
        [HttpGet("{id}")]
        [ProducesResponseType(typeof(QuizDTO), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<QuizDTO>> GetQuizByIdAsync(int id)
        {
            var quiz = await _quizService.GetQuizByIdAsync(id);
            return Ok(quiz);
        }

        // GET /api/quiz/{authorName}/quizzes

        /// <summary>
        /// Récupère la liste de tous les quiz créés par un auteur spécifique, avec leurs questions, réponses, images et tags.
        /// </summary>
        /// <param name="authorName">Le nom de l'auteur dont les quiz doivent être récupérés.</param>
        /// <param name="page">Le numéro de page (optionnel, par défaut à 1).</param>
        /// <param name="pageSize">Le nombre de quiz par page (optionnel, par défaut à 20, maximum 100).</param>
        /// <returns>La liste de tous les quiz créés par l'auteur spécifié, avec leurs questions, réponses, images et tags.</returns>
        /// <response code="200">La liste de tous les quiz créés par l'auteur spécifié, avec leurs questions, réponses, images et tags.</response>
        /// <response code="404">Non trouvé. Aucun quiz ne correspond au nom de l'auteur fourni.</response>
        [HttpGet("{authorName}/quizzes")]
        [ProducesResponseType(typeof(List<QuizDTO>), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<List<QuizDTO>>> GetQuizzesByAuthorNameAsync(string authorName, int page = 1, int pageSize = 20)
        {
            var quizzes = await _quizService.GetQuizzesByAuthorNameAsync(authorName, page, pageSize);
            return Ok(quizzes);
        }


        // POST /api/quiz

        /// <summary>
        /// Crée un nouveau quiz avec les données fournies et l'ID de l'auteur.
        /// </summary>
        /// <param name="dto">Les données du quiz à créer.</param>
        /// <returns>Le quiz créé avec les données fournies et l'ID de l'auteur.</returns>
        /// <response code="201">Le quiz créé avec les données fournies et l'ID de l'auteur.</response>
        /// <response code="400">Requête invalide. Les données du quiz sont manquantes ou invalides.</response>
        /// <response code="401">Non autorisé. L'utilisateur doit être authentifié pour créer un quiz.</response>
        [Authorize]
        [HttpPost("new")]
        [ProducesResponseType(typeof(QuizDTO), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<QuizDTO>> CreateQuizAsync([FromBody] CreateQuizDTO dto)
        {
            var authorId = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
            if (string.IsNullOrEmpty(authorId))
                return Unauthorized();

            var quiz = await _quizService.CreateQuizAsync(dto, authorId);
            return CreatedAtAction("GetQuizById", new { id = quiz.Id }, quiz);
        }

        // PATCH /api/quiz/{id}

        /// <summary>
        /// Met à jour un quiz existant avec les données fournies.
        /// </summary>
        /// <param name="id">L'ID du quiz à mettre à jour.</param>
        /// <param name="dto">Les données du quiz à mettre à jour.</param>
        /// <returns>Le quiz mis à jour avec les données fournies.</returns>
        /// <response code="200">Le quiz mis à jour avec les données fournies.</response>
        /// <response code="400">Requête invalide. Les données du quiz sont manquantes ou invalides.</response>
        /// <response code="404">Non trouvé. Aucun quiz ne correspond à l'ID fourni.</response>
        [Authorize]
        [HttpPatch("{id}")]
        [ProducesResponseType(typeof(QuizDTO), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<QuizDTO>> UpdateQuizAsync(int id, [FromBody] UpdateQuizDTO dto)
        {
            var authorId = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
            if (string.IsNullOrEmpty(authorId))
                return Unauthorized();

            var existingQuiz = await _quizService.GetQuizByIdAsync(id);
            if (existingQuiz.AuthorId != authorId)
                return Forbid();

            var updatedQuiz = await _quizService.UpdateQuizAsync(id, dto);
            return Ok(updatedQuiz);
        }

        // DELETE /api/quiz/{id}

        /// <summary>
        /// Supprime un quiz existant par son ID.
        /// </summary>
        /// <param name="id">L'ID du quiz à supprimer.</param>
        /// <returns>Aucun contenu.</returns>
        /// <response code="204">Aucun contenu. Le quiz a été supprimé avec succès.</response>
        /// <response code="404">Non trouvé. Aucun quiz ne correspond à l'ID fourni.</response>
        [Authorize]
        [HttpDelete("{id}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> DeleteQuizAsync(int id)
        {
            var authorId = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
            if (string.IsNullOrEmpty(authorId))
                return Unauthorized();

            var existingQuiz = await _quizService.GetQuizByIdAsync(id);
            if (existingQuiz.AuthorId != authorId)
                return Forbid();

            await _quizService.DeleteQuizAsync(id);
            return NoContent();
        }
    }
}