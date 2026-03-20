using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using MonAPIDotNet.Exceptions;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Service
{
    public interface IQuestionService
    {
        Task<QuestionDTO> CreateQuestionAsync(QuestionDTO dto, int quizId);
        Task<QuestionDTO> UpdateQuestionAsync(int id, QuestionDTO dto);
        Task DeleteQuestionAsync(int id);
        Task<List<QuestionDTO>> GetAllQuestionsAsync(int quizId, int page = 1, int pageSize = 20);
        Task<QuestionDTO> GetQuestionByIdAsync(int id);
    }
    public class QuestionService : IQuestionService
    {
        private readonly MyDbContext _context;

        public QuestionService(MyDbContext context)
        {
            _context = context;
        }

        public async Task<List<QuestionDTO>> GetAllQuestionsAsync(int quizId, int page = 1, int pageSize = 20)
        {
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100;

            var questions = await _context.Questions
                .Where(q => q.QuizId == quizId)
                .Include(q => q.Answers)
                .Include(q => q.Images)
                .OrderBy(q => q.Id)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return questions.Select(MapToDto).ToList();
        }

        public async Task<QuestionDTO> GetQuestionByIdAsync(int id)
        {
            var question = await _context.Questions
                .Include(q => q.Answers)
                .Include(q => q.Images)
                .FirstOrDefaultAsync(q => q.Id == id);

            if (question == null)
                throw new NotFoundException("Question", id);

            return MapToDto(question);
        }

        public async Task<QuestionDTO> CreateQuestionAsync(QuestionDTO dto, int quizId)
        {
            var question = new Question
            {
                Text = dto.Text,
                Type = Enum.TryParse<QuestionType>(dto.Type, out var type) ? type : QuestionType.MultipleChoice,
                IsTimed = dto.IsTimed,
                TimeLimit = dto.TimeLimit,
                Answers = dto.Answers?.Select(a => new Answer
                {
                    Value = a.Value,
                    IsCorrect = a.IsCorrect
                }).ToList() ?? new List<Answer>(),
                Images = dto.ImagesUrls?.Select(url => new QuestionImage
                {
                    Url = url
                }).ToList() ?? new List<QuestionImage>(),
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                QuizId = quizId,
            };

            _context.Questions.Add(question);
            await _context.SaveChangesAsync();

            return MapToDto(question);
        }

        public async Task<QuestionDTO> UpdateQuestionAsync(int id, QuestionDTO dto)
        {
            var question = await _context.Questions
                .Include(q => q.Answers)
                .Include(q => q.Images)
                .FirstOrDefaultAsync(q => q.Id == id);
            if (question == null)
                throw new NotFoundException("Question", id);

            question.Text = dto.Text;
            question.Type = Enum.TryParse<QuestionType>(dto.Type, out var type) ? type : QuestionType.MultipleChoice;
            
            // Update images
            question.Images.Clear();
            foreach (var url in dto.ImagesUrls ?? new List<string>())
            {
                question.Images.Add(new QuestionImage { Url = url });
            }
            // Update Answers
            question.Answers.Clear();
            foreach (var answer in dto.Answers ?? new List<AnswerDTO>())
            {
                question.Answers.Add(new Answer
                {
                    Value = answer.Value,
                    IsCorrect = answer.IsCorrect,
                    QuestionId = question.Id
                });
            }
            // Update other properties
            question.IsTimed = dto.IsTimed;
            question.TimeLimit = dto.TimeLimit;
            question.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return MapToDto(question);
        }

        public async Task DeleteQuestionAsync(int id)
        {
            var question = await _context.Questions.FindAsync(id);
            if (question == null)
                throw new NotFoundException("Question", id);

            _context.Questions.Remove(question);
            await _context.SaveChangesAsync();
        }
        
        private static QuestionDTO MapToDto(Question question)
        {
            return new QuestionDTO
            {
                Id = question.Id,
                Text = question.Text,
                Type = question.Type.ToString(),
                IsTimed = question.IsTimed,
                TimeLimit = question.TimeLimit,
                CreatedAt = question.CreatedAt,
                UpdatedAt = question.UpdatedAt,
                QuizId = question.QuizId,
                ImagesUrls = question.Images?.Select(i => i.Url).ToList() ?? new List<string>(),
                Answers = question.Answers?.Select(a => new AnswerDTO
                {
                    Id = a.Id,
                    Value = a.Value,
                    IsCorrect = a.IsCorrect,
                    QuestionId = a.QuestionId
                }).ToList() ?? new List<AnswerDTO>()
            };
        }
    }
}