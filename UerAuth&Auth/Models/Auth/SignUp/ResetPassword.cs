using System.ComponentModel.DataAnnotations;

namespace UerAuth_Auth.Models.Auth.SignUp
{
    public class ResetPassword
    {
        [Required]
        public string? Password { get; set; } = null;
        [Compare("Password", ErrorMessage = "The password and ConfirmPassword do not match.")]
        public string? ConfirmPassword { get; set; }
        [EmailAddress]
        public string? Email { get; set; } = null!;
        public string? Token { get; set; }

    }
}
