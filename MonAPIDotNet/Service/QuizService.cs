using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using MonAPIDotNet.Exceptions;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Service
{

    public interface IQuizService
    {
        Task<QuizDTO> CreateQuizAsync(CreateQuizDTO dto, string authorId);
        Task<QuizDTO> UpdateQuizAsync(int id, UpdateQuizDTO dto);
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
                Tags = quiz.QuizTags.Select(qt => new TagDto
                {
                    Id = qt.Tag.Id,
                    Name = qt.Tag.Name,
                    Color = qt.Tag.Color
                }).ToList(),
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
                TagIds = q.QuizTags.Select(qt => qt.TagId).ToList(),
                Tags = q.QuizTags.Select(qt => new TagDto
                {
                    Id = qt.Tag.Id,
                    Name = qt.Tag.Name,
                    Color = qt.Tag.Color
                }).ToList()
            }).ToList();
        }

        public async Task<QuizDTO> CreateQuizAsync(CreateQuizDTO dto, string authorId)
        {
            if (!Enum.TryParse<DifficultyType>(dto.Difficulty, out var difficulty))
            {
                difficulty = DifficultyType.Easy;
            }
            var quiz = new Quiz
            {
                Title = dto.Title,
                Description = dto.Description,
                Difficulty = difficulty,
                ImageUrl = dto.ImageUrl,
                AuthorId = authorId,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                QuizTags = dto.TagIds.Select(tagId => new QuizTag { TagId = tagId }).ToList()
            };

            _context.Quizzes.Add(quiz);
            await _context.SaveChangesAsync();

            var created = await _context.Quizzes
                .Include(q => q.Author)
                .Include(q => q.QuizTags)
                    .ThenInclude(qt => qt.Tag)
                .FirstAsync(q => q.Id == quiz.Id);

            return new QuizDTO
            {
                Id = created.Id,
                Title = created.Title,
                Description = created.Description,
                Difficulty = created.Difficulty.ToString(),
                ImageUrl = created.ImageUrl,
                AuthorId = created.AuthorId,
                AuthorName = created.Author?.UserName ?? "Unknown",
                CreatedAt = created.CreatedAt,
                UpdatedAt = created.UpdatedAt,
                TagIds = created.QuizTags.Select(qt => qt.TagId).ToList(),
                Tags = created.QuizTags.Select(qt => new TagDto
                {
                    Id = qt.Tag.Id,
                    Name = qt.Tag.Name,
                    Color = qt.Tag.Color
                }).ToList()
            };
        }

        public async Task<QuizDTO> UpdateQuizAsync(int id, UpdateQuizDTO dto)
        {
            var quiz = await _context.Quizzes.FindAsync(id);
            if (quiz == null)
                throw new NotFoundException("Quiz", id);

            quiz.Title = dto.Title;
            quiz.Description = dto.Description;
            quiz.Difficulty = Enum.Parse<DifficultyType>(dto.Difficulty);
            quiz.ImageUrl = dto.ImageUrl;
            quiz.UpdatedAt = DateTime.UtcNow;

            // Mettre à jour les questions
            if (dto.Questions != null)
            {
                var existingQuestions = await _context.Questions
                    .Include(q => q.Answers)
                    .Include(q => q.Images)
                    .Where(q => q.QuizId == id)
                    .ToListAsync();

                // Supprimer les questions qui ne sont plus dans le DTO
                var dtoQuestionIds = dto.Questions.Where(q => q.Id > 0).Select(q => q.Id).ToHashSet();
                var toRemove = existingQuestions.Where(q => !dtoQuestionIds.Contains(q.Id)).ToList();
                _context.Questions.RemoveRange(toRemove);

                foreach (var questionDto in dto.Questions)
                {
                    if (questionDto.Id > 0)
                    {
                        // Mise à jour d'une question existante
                        var existing = existingQuestions.FirstOrDefault(q => q.Id == questionDto.Id);
                        if (existing != null)
                        {
                            existing.Text = questionDto.Text;
                            existing.Type = Enum.Parse<QuestionType>(questionDto.Type);
                            existing.UpdatedAt = DateTime.UtcNow;

                            // Remplacer les réponses
                            _context.Answers.RemoveRange(existing.Answers);
                            existing.Answers = questionDto.Answers.Select(a => new Answer
                            {
                                QuestionId = existing.Id,
                                Value = a.Value,
                                IsCorrect = a.IsCorrect
                            }).ToList();

                            // Remplacer les images
                            _context.QuestionImages.RemoveRange(existing.Images);
                            existing.Images = questionDto.ImagesUrls.Select((url, i) => new QuestionImage
                            {
                                QuestionId = existing.Id,
                                Url = url,
                                Order = i
                            }).ToList();
                        }
                    }
                    else
                    {
                        // Nouvelle question
                        var newQuestion = new Question
                        {
                            QuizId = id,
                            Text = questionDto.Text,
                            Type = Enum.Parse<QuestionType>(questionDto.Type),
                            CreatedAt = DateTime.UtcNow,
                            Answers = questionDto.Answers.Select(a => new Answer
                            {
                                Value = a.Value,
                                IsCorrect = a.IsCorrect
                            }).ToList(),
                            Images = questionDto.ImagesUrls.Select((url, i) => new QuestionImage
                            {
                                Url = url,
                                Order = i
                            }).ToList()
                        };
                        _context.Questions.Add(newQuestion);
                    }
                    if (dto.TagIds != null)
                    {
                        var existingTags = await _context.QuizTags
                            .Where(qt => qt.QuizId == id)
                            .ToListAsync();

                        _context.QuizTags.RemoveRange(existingTags);

                        foreach (var tagId in dto.TagIds)
                        {
                            _context.QuizTags.Add(new QuizTag
                            {
                                QuizId = id,
                                TagId = tagId
                            });
                        }
                    }
                }
            }
            

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
                Questions = quiz.Questions.Select(q => new QuestionDTO
                {
                    Id = q.Id,
                    QuizId = q.QuizId,
                    Text = q.Text,
                    Type = q.Type.ToString(),
                    CreatedAt = q.CreatedAt,
                    UpdatedAt = q.UpdatedAt,
                    ImagesUrls = q.Images.Select(qi => qi.Url).ToList(),
                    Answers = q.Answers.Select(a => new AnswerDTO
                    {
                        Id = a.Id,
                        QuestionId = a.QuestionId,
                        Value = a.Value,
                        IsCorrect = a.IsCorrect
                    }).ToList()
                }).ToList(),
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
