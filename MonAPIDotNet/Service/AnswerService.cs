using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Service
{
    public interface IAnswerService
    {
        Task<AnswerDTO> CreateAnswerAsync(AnswerDTO Dto, int questionId);
        Task<AnswerDTO> UpdateAnswerAsync(int id, AnswerDTO dto);
        Task<bool> DeleteAnswerAsync(int id);
        Task<List<AnswerDTO>> GetAllAnswersAsync();
        Task<AnswerDTO> GetAnswerByIdAsync(int id);
    }
    public class AnswerService : IAnswerService
    {
        private readonly MyDbContext _context;

        public AnswerService(MyDbContext context)
        {
            _context = context;
        }

        public async Task<AnswerDTO> CreateAnswerAsync(AnswerDTO dto, int questionId)
        {
            var answer = new Answer
            {
                Value = dto.Value,
                IsCorrect = dto.IsCorrect,
                QuestionId = questionId,
            };

            _context.Answers.Add(answer);
            await _context.SaveChangesAsync();

            return new AnswerDTO
            {
                Id = answer.Id,
                Value = answer.Value,
                IsCorrect = answer.IsCorrect,
                QuestionId = answer.QuestionId
            };
        }

        public async Task<AnswerDTO> UpdateAnswerAsync(int id, AnswerDTO dto)
        {
            var answer = await _context.Answers.FindAsync(id);
            if (answer == null) return null;

            answer.Value = dto.Value;
            answer.IsCorrect = dto.IsCorrect;

            await _context.SaveChangesAsync();

            return new AnswerDTO
            {
                Id = answer.Id,
                Value = answer.Value,
                IsCorrect = answer.IsCorrect,
                QuestionId = answer.QuestionId
            };
        }

        public async Task<bool> DeleteAnswerAsync(int id)
        {
            var answer = await _context.Answers.FindAsync(id);
            if (answer == null) return false;

            _context.Answers.Remove(answer);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<List<AnswerDTO>> GetAllAnswersAsync()
        {
            var answers = await _context.Answers.ToListAsync();
            return answers.Select(a => new AnswerDTO
            {
                Id = a.Id,
                Value = a.Value,
                IsCorrect = a.IsCorrect,
                QuestionId = a.QuestionId
            }).ToList();
        }

        public async Task<AnswerDTO> GetAnswerByIdAsync(int id)
        {
            var answer = await _context.Answers.FindAsync(id);
            if (answer == null) return null;

            return new AnswerDTO
            {
                Id = answer.Id,
                Value = answer.Value,
                IsCorrect = answer.IsCorrect,
                QuestionId = answer.QuestionId
            };
        }
    }
}