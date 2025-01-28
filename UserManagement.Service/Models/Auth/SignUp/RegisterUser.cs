using System.ComponentModel.DataAnnotations;

namespace UserManagement.Service.Models.Auth.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "User name is required")]
        public string? Name { get; set; }
        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string? Email { get; set; }
        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
        [Required(ErrorMessage = "Role is required")]
        public List<string>? Roles { get; set; }
    }
}
