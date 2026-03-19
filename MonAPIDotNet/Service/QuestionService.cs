using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Service
{
    public interface IQuestionService
    {
        Task<QuestionDTO> CreateQuestionAsync(QuestionDTO Dto, int quizId);
        Task<QuestionDTO> UpdateQuestionAsync(int id, QuestionDTO dto);
        Task<bool> DeleteQuestionAsync(int id);
        Task<List<QuestionDTO>> GetAllQuestionsAsync();
        Task<QuestionDTO> GetQuestionByIdAsync(int id);
    }
    public class QuestionService : IQuestionService
    {
        private readonly MyDbContext _context;

        public QuestionService(MyDbContext context)
        {
            _context = context;
        }

        public async Task<QuestionDTO> CreateQuestionAsync(QuestionDTO dto, int quizId)
        {
            var question = new Question
            {
                Text = dto.Text,
                Type = Enum.Parse<QuestionType>(dto.Type),
                IsTimed = dto.IsTimed,
                TimeLimit = dto.TimeLimit,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                QuizId = quizId,
            };

            _context.Questions.Add(question);
            await _context.SaveChangesAsync();

            return new QuestionDTO
            {
                Id = question.Id,
                Text = question.Text,
                Type = question.Type.ToString(),
                IsTimed = question.IsTimed,
                TimeLimit = question.TimeLimit,
                CreatedAt = question.CreatedAt,
                UpdatedAt = question.UpdatedAt,
                QuizId = question.QuizId
            };
        }

        public async Task<QuestionDTO> UpdateQuestionAsync(int id, QuestionDTO dto)
        {
            var question = await _context.Questions.FindAsync(id);
            if (question == null) return null;

            question.Text = dto.Text;
            question.Type = Enum.Parse<QuestionType>(dto.Type);
            question.IsTimed = dto.IsTimed;
            question.TimeLimit = dto.TimeLimit;
            question.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return new QuestionDTO
            {
                Id = question.Id,
                Text = question.Text,
                Type = question.Type.ToString(),
                IsTimed = question.IsTimed,
                TimeLimit = question.TimeLimit,
                CreatedAt = question.CreatedAt,
                UpdatedAt = question.UpdatedAt,
                QuizId = question.QuizId
            };
        }

        public async Task<bool> DeleteQuestionAsync(int id)
        {
            var question = await _context.Questions.FindAsync(id);
            if (question == null) return false;

            _context.Questions.Remove(question);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<List<QuestionDTO>> GetAllQuestionsAsync()
        {
            var questions = await _context.Questions
                .Include(q => q.Answers)
                .Include(q => q.Images)
                .ToListAsync();

            return questions.Select(q => new QuestionDTO
            {
                Id = q.Id,
                Text = q.Text,
                Type = q.Type.ToString(),
                IsTimed = q.IsTimed,
                TimeLimit = q.TimeLimit,
                CreatedAt = q.CreatedAt,
                UpdatedAt = q.UpdatedAt,
                QuizId = q.QuizId,
                ImagesUrls = q.Images.Select(i => i.Url).ToList(),
                Answers = q.Answers.Select(a => new AnswerDTO { }).ToList()
            }).ToList();
        }

        public async Task<QuestionDTO> GetQuestionByIdAsync(int id)
        {
            var question = await _context.Questions.FindAsync(id);
            if (question == null) return null;

            return new QuestionDTO
            {
                Id = question.Id,
                Text = question.Text,
                Type = question.Type.ToString(),
                IsTimed = question.IsTimed,
                TimeLimit = question.TimeLimit,
                CreatedAt = question.CreatedAt,
                UpdatedAt = question.UpdatedAt,
                QuizId = question.QuizId
            };
        }
    }
}