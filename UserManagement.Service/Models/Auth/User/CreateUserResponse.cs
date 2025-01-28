using Microsoft.AspNetCore.Identity;
using System;


namespace UserManagement.Service.Models.Auth.User
{
    public class CreateUserResponse
    {
        public string? Token { get; set; } 
        public IdentityUser? User { get; set; }
    }
}
