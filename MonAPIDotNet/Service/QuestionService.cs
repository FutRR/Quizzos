using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using MonAPIDotNet.Exceptions;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Service
{
    public interface IQuestionService
    {
        Task<QuestionDTO> CreateQuestionAsync(QuestionDTO Dto, int quizId);
        Task<QuestionDTO> UpdateQuestionAsync(int id, QuestionDTO dto);
        Task<bool> DeleteQuestionAsync(int id);
        Task<List<QuestionDTO>> GetAllQuestionsAsync(int page = 1, int pageSize = 20);
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
            if (question == null)
                throw new NotFoundException("Question", id);

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
            if (question == null)
                throw new NotFoundException("Question", id);

            _context.Questions.Remove(question);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<List<QuestionDTO>> GetAllQuestionsAsync(int page = 1, int pageSize = 20)
        {
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100;

            var questions = await _context.Questions
                .Include(q => q.Answers)
                .Include(q => q.Images)
                .OrderBy(q => q.Id)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
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
                Answers = q.Answers.Select(a => new AnswerDTO
                {
                    Id = a.Id,
                    Value = a.Value,
                    IsCorrect = a.IsCorrect,
                    QuestionId = a.QuestionId
                }).ToList()
            }).ToList();
        }

        public async Task<QuestionDTO> GetQuestionByIdAsync(int id)
        {
            var question = await _context.Questions
                .Include(q => q.Answers)
                .Include(q => q.Images)
                .FirstOrDefaultAsync(q => q.Id == id);

            if (question == null)
                throw new NotFoundException("Question", id);

            return new QuestionDTO
            {
                Id = question.Id,
                Text = question.Text,
                Type = question.Type.ToString(),
                ImagesUrls = question.Images.Select(i => i.Url).ToList(),
                Answers = question.Answers.Select(a => new AnswerDTO
                {
                    Id = a.Id,
                    Value = a.Value,
                    IsCorrect = a.IsCorrect,
                    QuestionId = a.QuestionId
                }).ToList(),
                IsTimed = question.IsTimed,
                TimeLimit = question.TimeLimit,
                CreatedAt = question.CreatedAt,
                UpdatedAt = question.UpdatedAt,
                QuizId = question.QuizId
            };
        }
    }
}