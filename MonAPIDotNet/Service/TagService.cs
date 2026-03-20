using MonAPIDotNet.Data;
using MonAPIDotNet.DTOs;
using Microsoft.EntityFrameworkCore;

namespace MonAPIDotNet.Service
{
    public interface ITagService
    {
        Task<TagDto?> CreateTagAsync(CreateTagDto dto);
        Task<List<TagDto>> GetAllTagsAsync();
        Task<TagDto?> GetTagByIdAsync(int id);
        Task<TagDto?> GetTagByNameAsync(string name);
        Task<TagDto?> UpdateTagAsync(int id, UpdateTagDto dto);
        Task<bool> DeleteTagAsync(int id);
        Task<List<TagDto>> SearchTagsAsync(string query);
    }

    public class TagService : ITagService
    {
        private readonly MyDbContext _context;

        public TagService(MyDbContext context)
        {
            _context = context;
        }

        public async Task<TagDto?> CreateTagAsync(CreateTagDto dto)
        {
            // Vérifier si le tag existe déjà
            var existingTag = await _context.Tags
                .FirstOrDefaultAsync(t => t.Name.ToLower() == dto.Name.ToLower());
            
            if (existingTag != null)
                return null;

            var tag = new Tag
            {
                Name = dto.Name.ToLower().Trim(),
                Color = dto.Color ?? "#6366f1",
                CreatedAt = DateTime.UtcNow
            };

            _context.Tags.Add(tag);
            await _context.SaveChangesAsync();

            return MapToDto(tag);
        }

        public async Task<List<TagDto>> GetAllTagsAsync()
        {
            return await _context.Tags
                .OrderBy(t => t.Name)
                .Select(t => MapToDto(t))
                .ToListAsync();
        }

        public async Task<TagDto?> GetTagByIdAsync(int id)
        {
            var tag = await _context.Tags.FindAsync(id);
            return tag != null ? MapToDto(tag) : null;
        }

        public async Task<TagDto?> GetTagByNameAsync(string name)
        {
            var tag = await _context.Tags
                .FirstOrDefaultAsync(t => t.Name.ToLower() == name.ToLower());
            return tag != null ? MapToDto(tag) : null;
        }

        public async Task<TagDto?> UpdateTagAsync(int id, UpdateTagDto dto)
        {
            var tag = await _context.Tags.FindAsync(id);
            if (tag == null)
                return null;

            if (!string.IsNullOrEmpty(dto.Name))
                tag.Name = dto.Name.ToLower().Trim();
            
            if (!string.IsNullOrEmpty(dto.Color))
                tag.Color = dto.Color;

            await _context.SaveChangesAsync();
            return MapToDto(tag);
        }

        public async Task<bool> DeleteTagAsync(int id)
        {
            var tag = await _context.Tags.FindAsync(id);
            if (tag == null)
                return false;

            _context.Tags.Remove(tag);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<List<TagDto>> SearchTagsAsync(string query)
        {
            return await _context.Tags
                .Where(t => t.Name.Contains(query.ToLower()))
                .OrderBy(t => t.Name)
                .Take(10)
                .Select(t => MapToDto(t))
                .ToListAsync();
        }

        private static TagDto MapToDto(Tag tag)
        {
            return new TagDto
            {
                Id = tag.Id,
                Name = tag.Name,
                Color = tag.Color
            };
        }
    }
}