using Microsoft.AspNetCore.Identity;
using User.Management.Data.Data;

namespace UerAuth_Auth.Models
{
    public class ToDo
    {
        public int Id { get; set; }
        public string? Title { get; set; }
        public string? Description { get; set; }
        public bool isCompleted { get; set; }
        public string? ApplicationUserId { get; set; }

        public ApplicationUser? user { get; set; }
    }
}
