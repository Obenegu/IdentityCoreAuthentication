using Microsoft.AspNetCore.Identity;
using System;
using User.Management.Data.Data;


namespace UserManagement.Service.Models.Auth.User
{
    public class CreateUserResponse
    {
        public string? Token { get; set; } 
        public ApplicationUser? User { get; set; }
    }
}
