namespace MonAPIDotNet.Service
{
    public interface IQuestionService
    {
        Task<List<QuestionDTO>> GetAllQuestionsAsync();
        Task<QuestionDTO> GetQuestionByIdAsync(int id);
        Task<List<QuestionDTO>> GetQuestionsByUserIdAsync(string userId);
        Task<QuestionDTO> CreateQuestionAsync(QuestionCreateDTO questionDto, string userId);
        Task<bool> UpdateQuestionAsync(int id, QuestionUpdateDTO questionDto, string userId);
        Task<bool> DeleteQuestionAsync(int id, string userId);
    }
    public class QuestionService : IQuestionService
    {
        private readonly MyDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public QuestionService(MyDbContext context, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        // Implement the methods defined in the interface here...
    }
}