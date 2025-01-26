using Microsoft.AspNetCore.Identity;

namespace UerAuth_Auth.Models
{
    public class ToDo
    {
        public int Id { get; set; }
        public string? Title { get; set; }
        public string? Description { get; set; }
        public bool isCompleted { get; set; }
        public string? IdentityUserId { get; set; }

        public IdentityUser? user { get; set; }
    }
}
