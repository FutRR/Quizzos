using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Service
{

    public interface IQuizService
    {
        Task<QuizDTO> CreateQuizAsync(QuizDTO dto, string authorId);
        Task<QuizDTO> UpdateQuizAsync(int id, QuizDTO dto);
        Task<bool> DeleteQuizAsync(int id);

        Task<List<QuizDTO>> GetAllQuizzesAsync();
        Task<QuizDTO> GetQuizByIdAsync(int id);
    }

    public class QuizService : IQuizService
    {
        private readonly MyDbContext _context;

        public QuizService(MyDbContext context)
        {
            _context = context;
        }
        
        public async Task<QuizDTO> CreateQuizAsync(QuizDTO dto, string authorId)
        {
            var quiz = new Quiz
            {
                Title = dto.Title,
                Description = dto.Description,
                Difficulty = Enum.Parse<DifficultyType>(dto.Difficulty),
                ImageUrl = dto.ImageUrl,
                AuthorId = authorId,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };
            
            _context.Quizzes.Add(quiz);
            await _context.SaveChangesAsync();
            
            return new QuizDTO
            {
                Id = quiz.Id,
                Title = quiz.Title,
                Description = quiz.Description,
                Difficulty = quiz.Difficulty.ToString(),
                ImageUrl = quiz.ImageUrl,
                AuthorId = quiz.AuthorId,
                CreatedAt = quiz.CreatedAt,
                UpdatedAt = quiz.UpdatedAt
            };
        }

        public async Task<QuizDTO> UpdateQuizAsync(int id, QuizDTO dto)
        {
            var quiz = await _context.Quizzes.FindAsync(id);
            if (quiz == null) return null;
            
            quiz.Title = dto.Title;
            quiz.Description = dto.Description;
            quiz.Difficulty = Enum.Parse<DifficultyType>(dto.Difficulty);
            quiz.ImageUrl = dto.ImageUrl;
            quiz.UpdatedAt = DateTime.UtcNow;
            
            await _context.SaveChangesAsync();
            
            return new QuizDTO
            {
                Id = quiz.Id,
                Title = quiz.Title,
                Description = quiz.Description,
                Difficulty = quiz.Difficulty.ToString(),
                ImageUrl = quiz.ImageUrl,
                AuthorId = quiz.AuthorId,
                CreatedAt = quiz.CreatedAt,
                UpdatedAt = quiz.UpdatedAt
            };
        }

        public async Task<bool> DeleteQuizAsync(int id)
        {
            var quiz = await _context.Quizzes.FindAsync(id);
            if (quiz == null) return false;
            
            _context.Quizzes.Remove(quiz);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<List<QuizDTO>> GetAllQuizzesAsync()
        {
            var quizzes = await _context.Quizzes
                .Include(q => q.Author)
                .Include(q => q.Questions)
                .Include(q => q.QuizTags)
                    .ThenInclude(qt => qt.Tag)
                .ToListAsync();

            return quizzes.Select(q => new QuizDTO
            {
                Id = q.Id,
                Title = q.Title,
                Description = q.Description ?? string.Empty,
                Difficulty = q.Difficulty.ToString(),
                ImageUrl = q.ImageUrl,
                AuthorId = q.AuthorId,
                AuthorName = q.Author?.UserName ?? string.Empty,
                CreatedAt = q.CreatedAt,
                UpdatedAt = q.UpdatedAt,
                Questions = q.Questions.Select(question => new QuestionDTO {}).ToList(),
                TagIds = q.QuizTags.Select(qt => qt.TagId).ToList()
            }).ToList();
        }

        public async Task<QuizDTO> GetQuizByIdAsync(int id)
        {
            var quiz = await _context.Quizzes
                .Include(q => q.Author)
                .Include(q => q.Questions)
                .Include(q => q.QuizTags)
                    .ThenInclude(qt => qt.Tag)
                .FirstOrDefaultAsync(q => q.Id == id);

            if (quiz == null) return null;
            
            return new QuizDTO
            {
                Id = quiz.Id,
                Title = quiz.Title,
                Description = quiz.Description ?? string.Empty,
                AuthorId = quiz.AuthorId,
                CreatedAt = quiz.CreatedAt,
                UpdatedAt = quiz.UpdatedAt
            };
        }
    }


}