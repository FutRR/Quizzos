using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using MonAPIDotNet.Exceptions;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Service
{
    public interface IAnswerService
    {
        Task<AnswerDTO> CreateAnswerAsync(AnswerDTO Dto, int questionId);
        Task<AnswerDTO> UpdateAnswerAsync(int id, AnswerDTO dto);
        Task<bool> DeleteAnswerAsync(int id);
        Task<List<AnswerDTO>> GetAllAnswersAsync(int page = 1, int pageSize = 20);
        Task<AnswerDTO> GetAnswerByIdAsync(int id);
    }
    public class AnswerService : IAnswerService
    {
        private readonly MyDbContext _context;

        public AnswerService(MyDbContext context)
        {
            _context = context;
        }

        public async Task<List<AnswerDTO>> GetAllAnswersAsync(int page = 1, int pageSize = 20)
        {
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 100) pageSize = 100;

            var answers = await _context.Answers
                .OrderBy(a => a.Id)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return answers.Select(MapToDto).ToList();
        }

        public async Task<AnswerDTO> GetAnswerByIdAsync(int id)
        {
            var answer = await _context.Answers.FindAsync(id);
            if (answer == null)
                throw new NotFoundException("Answer", id);

            return MapToDto(answer);
        }

        public async Task<AnswerDTO> CreateAnswerAsync(AnswerDTO dto, int questionId)
        {
            var questionExists = await _context.Questions.AnyAsync(q => q.Id == questionId);
            if (!questionExists)
                throw new NotFoundException("Question", questionId);

            if (string.IsNullOrWhiteSpace(dto.Value))
                throw new ArgumentException("Answer value cannot be empty.");

            if (dto.Value.Length > 50)
                throw new ArgumentException("Answer value cannot exceed 50 characters.");

            var answer = new Answer
            {
                Value = dto.Value,
                IsCorrect = dto.IsCorrect,
                QuestionId = questionId,
            };

            try
            {
                _context.Answers.Add(answer);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException ex)
            {
                throw new InvalidOperationException("Failed to create answer.", ex);
            }

            return MapToDto(answer);
        }

        public async Task<AnswerDTO> UpdateAnswerAsync(int id, AnswerDTO dto)
        {
            var answer = await _context.Answers.FindAsync(id);
            if (answer == null)
                throw new NotFoundException("Answer", id);

            if (string.IsNullOrWhiteSpace(dto.Value))
                throw new ArgumentException("Answer value cannot be empty.");

            if (dto.Value.Length > 50)
                throw new ArgumentException("Answer value cannot exceed 50 characters.");

            answer.Value = dto.Value;
            answer.IsCorrect = dto.IsCorrect;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException ex)
            {
                throw new InvalidOperationException("Failed to update answer.", ex);
            }

            return MapToDto(answer);
        }

        public async Task<bool> DeleteAnswerAsync(int id)
        {
            var answer = await _context.Answers.FindAsync(id);
            if (answer == null)
                throw new NotFoundException("Answer", id);

            try
            {
                _context.Answers.Remove(answer);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException ex)
            {
                throw new InvalidOperationException("Failed to delete answer.", ex);
            }

            return true;
        }

        private static AnswerDTO MapToDto(Answer answer)
        {
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