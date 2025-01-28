using Microsoft.AspNetCore.Identity;
using UserManagement.Service.Models;
using UserManagement.Service.Models.Auth.SignUp;
using UserManagement.Service.Models.Auth.User;

namespace UserManagement.Service.Services
{
    public interface IUserManagement
    {
        //<summary>
        //Brief history of what the method does
        //</summary>
        //<param name="registerUser">Description of the parameter</param>
        //<returns>Description of the return value</returns>
        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser);
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> role, IdentityUser user);
    }
}
