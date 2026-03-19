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
            quiz.UpdatedAt = DateTime.UtcNow;
            
            await _context.SaveChangesAsync();
            
            return new QuizDTO
            {
                Id = quiz.Id,
                Title = quiz.Title,
                Description = quiz.Description,
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
            var quizzes = await _context.Quizzes.ToListAsync();
            return quizzes.Select(q => new QuizDTO
            {
                Id = q.Id,
                Title = q.Title,
                Description = q.Description,
                AuthorId = q.AuthorId,
                CreatedAt = q.CreatedAt,
                UpdatedAt = q.UpdatedAt
            }).ToList();
        }

        public async Task<QuizDTO> GetQuizByIdAsync(int id)
        {
            var quiz = await _context.Quizzes.FindAsync(id);
            if (quiz == null) return null;
            
            return new QuizDTO
            {
                Id = quiz.Id,
                Title = quiz.Title,
                Description = quiz.Description,
                AuthorId = quiz.AuthorId,
                CreatedAt = quiz.CreatedAt,
                UpdatedAt = quiz.UpdatedAt
            };
        }
    }


}