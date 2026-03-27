using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using MonAPIDotNet.Exceptions;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Service
{

    public interface IQuizService
    {
        Task<QuizDTO> CreateQuizAsync(CreateQuizDTO dto, string authorId);
        Task<QuizDTO> UpdateQuizAsync(int id, QuizDTO dto);
        Task DeleteQuizAsync(int id);

        Task<List<QuizDTO>> GetAllQuizzesAsync(int page = 1, int pageSize = 20);
        Task<QuizDTO> GetQuizByIdAsync(int id);
        Task<List<QuizDTO>> GetQuizzesByAuthorNameAsync(string authorName, int page = 1, int pageSize = 20);
    }

    public class QuizService : IQuizService
    {
        private readonly MyDbContext _context;

        public QuizService(MyDbContext context)
        {
            _context = context;
        }

        public async Task<List<QuizDTO>> GetAllQuizzesAsync(int page = 1, int pageSize = 20)
        {
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100;

            var quizzes = await _context.Quizzes
                .Include(q => q.Author)
                .Include(q => q.Questions)
                    .ThenInclude(q => q.Images)
                .Include(q => q.Questions)
                    .ThenInclude(q => q.Answers)
                .Include(q => q.QuizTags)
                    .ThenInclude(qt => qt.Tag)
                .OrderBy(q => q.Id)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
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
                Tags = q.QuizTags.Select(qt => new TagDto
                { 
                    Id = qt.Tag.Id, 
                    Name = qt.Tag.Name, 
                    Color = qt.Tag.Color 
                }).ToList(),
                Questions = q.Questions.Select(question => new QuestionDTO
                {
                    Id = question.Id,
                    Text = question.Text,
                    Type = question.Type.ToString(),
                    IsTimed = question.IsTimed,
                    TimeLimit = question.TimeLimit,
                    CreatedAt = question.CreatedAt,
                    UpdatedAt = question.UpdatedAt,
                    QuizId = question.QuizId,
                    ImagesUrls = question.Images.Select(qi => qi.Url).ToList(),
                    Answers = question.Answers.Select(answer => new AnswerDTO
                    {
                        Id = answer.Id,
                        Value = answer.Value,
                        IsCorrect = answer.IsCorrect,
                        QuestionId = answer.QuestionId
                    }).ToList()
                }).ToList(),
                TagIds = q.QuizTags.Select(qt => qt.TagId).ToList()
            }).ToList();
        }

        public async Task<QuizDTO> GetQuizByIdAsync(int id)
        {
            var quiz = await _context.Quizzes
                .Include(q => q.Author)
                .Include(q => q.Questions)
                    .ThenInclude(q => q.Images)
                .Include(q => q.Questions)
                    .ThenInclude(q => q.Answers)
                .Include(q => q.QuizTags)
                    .ThenInclude(qt => qt.Tag)
                .FirstOrDefaultAsync(q => q.Id == id);

            if (quiz == null)
                throw new NotFoundException("Quiz", id);

            return new QuizDTO
            {
                Id = quiz.Id,
                Title = quiz.Title,
                Description = quiz.Description ?? string.Empty,
                Difficulty = quiz.Difficulty.ToString(),
                ImageUrl = quiz.ImageUrl,
                AuthorName = quiz.Author?.UserName ?? string.Empty,
                Questions = quiz.Questions.Select(question => new QuestionDTO
                {
                    Id = question.Id,
                    Text = question.Text,
                    Type = question.Type.ToString(),
                    IsTimed = question.IsTimed,
                    TimeLimit = question.TimeLimit,
                    CreatedAt = question.CreatedAt,
                    UpdatedAt = question.UpdatedAt,
                    QuizId = question.QuizId,
                    ImagesUrls = question.Images.Select(qi => qi.Url).ToList(),
                    Answers = question.Answers.Select(answer => new AnswerDTO
                    {
                        Id = answer.Id,
                        Value = answer.Value,
                        IsCorrect = answer.IsCorrect,
                        QuestionId = answer.QuestionId
                    }).ToList()
                }).ToList(),
                TagIds = quiz.QuizTags.Select(qt => qt.TagId).ToList(),
                AuthorId = quiz.AuthorId,
                CreatedAt = quiz.CreatedAt,
                UpdatedAt = quiz.UpdatedAt
            };
        }

        public async Task<List<QuizDTO>> GetQuizzesByAuthorNameAsync(string authorName, int page = 1, int pageSize = 20)
        {
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100;

            var quizzes = await _context.Quizzes
                .Where(q => q.Author.UserName == authorName)
                .Include(q => q.Author)
                .Include(q => q.Questions)
                    .ThenInclude(q => q.Images)
                .Include(q => q.Questions)
                    .ThenInclude(q => q.Answers)
                .Include(q => q.QuizTags)
                    .ThenInclude(qt => qt.Tag)
                .OrderBy(q => q.Id)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
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
                Questions = q.Questions.Select(question => new QuestionDTO
                {
                    Id = question.Id,
                    Text = question.Text,
                    Type = question.Type.ToString(),
                    IsTimed = question.IsTimed,
                    TimeLimit = question.TimeLimit,
                    CreatedAt = question.CreatedAt,
                    UpdatedAt = question.UpdatedAt,
                    QuizId = question.QuizId,
                    ImagesUrls = question.Images.Select(qi => qi.Url).ToList(),
                    Answers = question.Answers.Select(answer => new AnswerDTO
                    {
                        Id = answer.Id,
                        Value = answer.Value,
                        IsCorrect = answer.IsCorrect,
                        QuestionId = answer.QuestionId
                    }).ToList()
                }).ToList(),
                TagIds = q.QuizTags.Select(qt => qt.TagId).ToList()
            }).ToList();
        }

        public async Task<QuizDTO> CreateQuizAsync(CreateQuizDTO dto, string authorId)
        {
            var quiz = new Quiz
            {
                Title = dto.Title,
                Description = dto.Description,
                Difficulty = Enum.Parse<DifficultyType>(dto.Difficulty),
                ImageUrl = dto.ImageUrl,
                AuthorId = authorId,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                QuizTags = dto.TagIds.Select(tagId => new QuizTag { TagId = tagId }).ToList()
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
                UpdatedAt = quiz.UpdatedAt,
                TagIds = quiz.QuizTags.Select(qt => qt.TagId).ToList()
            };
        }

        public async Task<QuizDTO> UpdateQuizAsync(int id, QuizDTO dto)
        {
            var quiz = await _context.Quizzes.FindAsync(id);
            if (quiz == null)
                throw new NotFoundException("Quiz", id);

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
                UpdatedAt = quiz.UpdatedAt,
                TagIds = quiz.QuizTags.Select(qt => qt.TagId).ToList()
            };
        }

        public async Task DeleteQuizAsync(int id)
        {
            var quiz = await _context.Quizzes.FindAsync(id);
            if (quiz == null)
                throw new NotFoundException("Quiz", id);

            _context.Quizzes.Remove(quiz);
            await _context.SaveChangesAsync();
        }
    }


}