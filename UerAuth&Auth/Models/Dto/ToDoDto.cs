using Microsoft.AspNetCore.Identity;

namespace UerAuth_Auth.Models.Dto
{
    public class ToDoDto
    {
        public int Id { get; set; }
        public string? Title { get; set; }
        public string? Description { get; set; }
        public bool isCompleted { get; set; }
        public string? ApplicationUserId { get; set; }
        public string? UserName { get; set; }
    }
}
