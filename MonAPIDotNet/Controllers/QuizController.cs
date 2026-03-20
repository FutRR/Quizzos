using MonAPIDotNet.DTOs;
using MonAPIDotNet.Service;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace MonAPIDotNet.Controllers
{
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
            if (quizzes == null || quizzes.Count == 0)
            {
                return NotFound();
            }
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
            if (quiz == null)
                return NotFound();

            return Ok(quiz);
        }

        // POST /api/quiz/new

        /// <summary>
        /// Crée un nouveau quiz avec les données fournies et l'ID de l'auteur.
        /// </summary>
        /// <param name="dto">Les données du quiz à créer.</param>
        /// <returns>Le quiz créé avec les données fournies et l'ID de l'auteur.</returns>
        /// <response code="201">Le quiz créé avec les données fournies et l'ID de l'auteur.</response>
        /// <response code="400">Requête invalide. Les données du quiz sont manquantes ou invalides.</response>
        [Authorize]
        [HttpPost("new")]
        [ProducesResponseType(typeof(QuizDTO), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<QuizDTO>> CreateQuizAsync([FromBody] QuizDTO dto)
        {
            var authorId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (dto == null || string.IsNullOrEmpty(authorId))
                return BadRequest("Quiz data and author ID are required.");

            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var quiz = await _quizService.CreateQuizAsync(dto, authorId);
            return CreatedAtAction(nameof(GetQuizByIdAsync), new { id = quiz.Id }, quiz);
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
        public async Task<ActionResult<QuizDTO>> UpdateQuizAsync(int id, [FromBody] QuizDTO dto)
        {
            if (dto == null)
                return BadRequest("Quiz data is required.");

            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var updatedQuiz = await _quizService.UpdateQuizAsync(id, dto);
            if (updatedQuiz == null)
                return NotFound();

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
            var success = await _quizService.DeleteQuizAsync(id);
            if (!success)
                return NotFound();

            return NoContent();
        }
    }
}