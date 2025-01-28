using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using User.Management.Data.Data;
using UserManagement.Service.Models;
using UserManagement.Service.Models.Auth.SignUp;
using UserManagement.Service.Models.Auth.User;

namespace UserManagement.Service.Services
{
    public class UserManagementService : IUserManagement
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public UserManagementService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user)
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
            ApplicationUser user = new()
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

        public async Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user)
        {
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Email, user.Email!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
            //add roles to token
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var jwtToken = GetToken(authClaims); //access token
            var refreshToken = GenerateRefreshToken();
            _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int refreshTokenValidity);

            user.RefreshToken = refreshToken;
            user.TokenExpiry = DateTime.Now.AddDays(refreshTokenValidity);

            await _userManager.UpdateAsync(user);

            return new ApiResponse<LoginResponse>()
            {
                Response = new LoginResponse()
                {
                    AccessToken = new TokenTypes()
                    {
                        Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        ExpiryTokenDate = jwtToken.ValidTo
                    },
                    RefreshToken = new TokenTypes()
                    {
                        Token = user.RefreshToken,
                        ExpiryTokenDate = (DateTime)user.TokenExpiry
                    }
                },
                IsSuccess = true,
                StatusCode = 200,
                Message = $"Token created"
            };
        }

        public async Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens)
        {
            var accessToken = tokens.AccessToken;
            var refreshToken = tokens.RefreshToken;
            var principal = GetClaimsPrincipal(accessToken.Token);
            var email = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
            var user = await _userManager.FindByEmailAsync(email!);
            if(refreshToken.Token != user!.RefreshToken && refreshToken.ExpiryTokenDate<=DateTime.Now )
            {
                return new ApiResponse<LoginResponse>()
                {
                    IsSuccess = false,
                    StatusCode = 500,
                    Message = $"Invalid Token or token is expired"
                };
            }
            var response = await GetJwtTokenAsync(user);
            return response;
            
        }

        #region PrivateMethod
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);
            var expirationTimeUtc = DateTime.Now.AddMinutes(tokenValidityInMinutes);
            var localTimeZone = TimeZoneInfo.Local;
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: expirationTimeUtc,
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new Byte[64];
            var range = RandomNumberGenerator.Create();
            range.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal GetClaimsPrincipal(string accessToken)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);

            return principal;

        }

        #endregion
    }
}
