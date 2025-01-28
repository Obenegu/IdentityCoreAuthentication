using Microsoft.AspNetCore.Identity;
using UserManagement.Service.Models;
using UserManagement.Service.Models.Auth.SignUp;
using UserManagement.Service.Models.Auth.User;

namespace UserManagement.Service.Services
{
    public class UserManagementService : IUserManagement
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserManagementService(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, IdentityUser user)
        {
            var assignRole = new List<string>();
            foreach (var role in roles)
            {
                if( await _roleManager.RoleExistsAsync(role))
                {
                    if(!await _userManager.IsInRoleAsync(user, role))
                    {
                        await _userManager.AddToRoleAsync(user, role);
                        assignRole.Add(role);
                    }
                }
            }
            return new ApiResponse<List<string>>
            {
                IsSuccess = true,
                StatusCode = 200,
                Message = "Roles has been assigned",
                Response = assignRole
            }; 
        }

        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            // user already exists
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email!);
            if (userExist != null)
            {
                return new ApiResponse<CreateUserResponse> 
                { IsSuccess = false, StatusCode = 403, Message = "User Already exists"};
            }

            // user does not exist
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Name,
            };
            var result = await _userManager.CreateAsync(user, registerUser.Password!);
            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                return new ApiResponse<CreateUserResponse>
                { IsSuccess = true, StatusCode = 201, Message = "User Created Successfully", 
                    Response = new CreateUserResponse() { 
                            User = user,
                            Token = token
                    } };
            }
            else
            {
                return new ApiResponse<CreateUserResponse>
                { IsSuccess = false, StatusCode = 500, Message = "User Failed to create" };
            }
        }
    }
}
