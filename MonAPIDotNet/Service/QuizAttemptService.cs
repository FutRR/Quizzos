using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using MonAPIDotNet.Exceptions;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Service
{
    public interface IQuizAttemptService
    {
        Task<QuizAttemptResultDTO> SubmitQuizAsync(string userId, SubmitQuizDTO dto);
        Task<UserStatsDTO> GetUserStatsAsync(string userId);
    }

    public class QuizAttemptService : IQuizAttemptService
    {
        private readonly MyDbContext _context;

        public QuizAttemptService(MyDbContext context)
        {
            _context = context;
        }

        public async Task<QuizAttemptResultDTO> SubmitQuizAsync(string userId, SubmitQuizDTO dto)
        {
            // 1. Charger le quiz avec ses questions et réponses
            var quiz = await _context.Quizzes
                .Include(q => q.Questions)
                    .ThenInclude(q => q.Answers)
                .FirstOrDefaultAsync(q => q.Id == dto.QuizId);

            if (quiz == null)
                throw new NotFoundException("Quiz", dto.QuizId);

            // 2. Vérifier que toutes les questions sont couvertes
            int correctCount = 0;
            var results = new List<QuestionResultDTO>();

            foreach (var question in quiz.Questions)
            {
                var submitted = dto.Answers.FirstOrDefault(a => a.QuestionId == question.Id);
                var correctIds = question.Answers
                    .Where(a => a.IsCorrect)
                    .Select(a => a.Id)
                    .OrderBy(id => id)
                    .ToList();

                var selectedIds = (submitted?.SelectedOptionIds ?? new List<int>())
                    .OrderBy(id => id)
                    .ToList();

                // vérification des IDs soumis
                var validIds = question.Answers.Select(a => a.Id).ToHashSet();
                selectedIds = selectedIds.Where(id => validIds.Contains(id)).ToList();

                bool isCorrect = correctIds.SequenceEqual(selectedIds);
                if (isCorrect)
                    correctCount++;

                results.Add(new QuestionResultDTO
                {
                    QuestionId = question.Id,
                    IsCorrect = isCorrect,
                    SelectedAnswerIds = selectedIds,
                    CorrectAnswerIds = correctIds
                });
            }

            // 3. Calculer le score
            int total = quiz.Questions.Count;
            double percent = total > 0 ? Math.Round((double)correctCount / total * 100, 2) : 0;

            // 4. Vérifier si c'est la première tentative
            bool isFirstAttempt = !await _context.QuizAttempts
                .AnyAsync(a => a.UserId == userId && a.QuizId == dto.QuizId);

            // 5. Déterminer si c'est un nouveau meilleur score
            double? currentBestScore = await _context.QuizAttempts
                .Where(a => a.UserId == userId && a.QuizId == dto.QuizId)
                .MaxAsync(a => (double?)a.ScorePercentage);

            bool isNewBestScore = !currentBestScore.HasValue || percent > currentBestScore.Value;

            // 6. Persister la tentative
            var attempt = new QuizAttempt
            {
                UserId = userId,
                QuizId = dto.QuizId,
                CorrectAnswers = correctCount,
                TotalQuestions = total,
                ScorePercentage = percent,
                IsFirstAttempt = isFirstAttempt,
                CompletedAt = DateTime.UtcNow
            };

            _context.QuizAttempts.Add(attempt);
            await _context.SaveChangesAsync();

            return new QuizAttemptResultDTO
            {
                AttemptId = attempt.Id,
                QuizId = dto.QuizId,
                CorrectAnswers = correctCount,
                TotalQuestions = total,
                ScorePercent = percent,
                IsFirstAttempt = isFirstAttempt,
                IsNewBestScore = isNewBestScore,
                Results = results
            };
        }

        public async Task<UserStatsDTO> GetUserStatsAsync(string userId)
        {
            var attempts = _context.QuizAttempts
                .Where(a => a.UserId == userId);

            var bestPerQuiz = await attempts
                .GroupBy(a => a.QuizId)
                .Select(g => new { QuizId = g.Key, BestScore = g.Max(a => a.ScorePercentage) })
                .ToListAsync();

            var firstAttemptAvg = await attempts
                .Where(a => a.IsFirstAttempt)
                .AverageAsync(a => (double?)a.ScorePercentage);

            return new UserStatsDTO
            {
                QuizzesPlayed = bestPerQuiz.Count,
                TotalAttempts = await attempts.CountAsync(),
                AverageBestScorePercent = bestPerQuiz.Any()
                    ? Math.Round(bestPerQuiz.Average(x => x.BestScore), 2) : 0,
                FirstAttemptAverage = firstAttemptAvg.HasValue
                    ? Math.Round(firstAttemptAvg.Value, 2) : null
            };
        }
    }
}