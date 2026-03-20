using Microsoft.AspNetCore.Mvc;
using MonAPIDotNet.Service;
using MonAPIDotNet.DTOs;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;


namespace MonAPIDotNet.Controllers
{
    [ApiController]
    [Route("api/quiz/{quizId}/questions")]
    public class QuestionController : ControllerBase
    {
        private readonly IQuestionService _questionService;

        public QuestionController(IQuestionService questionService)
        {
            _questionService = questionService;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll(int quizId, int page = 1, int pageSize = 20)
        {
            var questions = await _questionService.GetAllQuestionsAsync(quizId, page, pageSize);
            return Ok(questions);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int quizId, int id)
        {
            var question = await _questionService.GetQuestionByIdAsync(id);
            return Ok(question);
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> Create(int quizId, [FromBody] QuestionDTO dto)
        {
            var question = await _questionService.CreateQuestionAsync(dto, quizId);
            return CreatedAtAction(nameof(GetById), new { quizId, id = question.Id }, question);
        }

        [Authorize]
        [HttpPut("{id}")]
        public async Task<IActionResult> Update(int quizId, int id, [FromBody] QuestionDTO dto)
        {
            var question = await _questionService.UpdateQuestionAsync(id, dto);
            return Ok(question);
        }

        [Authorize]
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(int quizId, int id)
        {
            await _questionService.DeleteQuestionAsync(id);
            return NoContent();
        }
    }
}
