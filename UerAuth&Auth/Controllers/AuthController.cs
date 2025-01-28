using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UerAuth_Auth.Models;
using UserManagement.Service.Services;
using UserManagement.Service.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;
using UserManagement.Service.Models.Auth.SignUp;
using UserManagement.Service.Models.Auth.Login;

namespace UerAuth_Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IUserManagement _user;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IEmailService emailService, IConfiguration configuration, IUserManagement user)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _user = user;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {

            var tokenResponse = await _user.CreateUserWithTokenAsync(registerUser);
            if(tokenResponse.IsSuccess)
            {
                await _user.AssignRoleToUserAsync(registerUser.Roles!, tokenResponse.Response!.User!);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Auth",
                    new { tokenResponse.Response.Token, email = registerUser.Email }, Request.Scheme);
                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status201Created,
                            new Response { Status = "Success", Message = "User account created successfully" });
            }

            return StatusCode(StatusCodes.Status201Created,
                            new Response { IsSuccess = false, Message = tokenResponse.Message });
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> LoginUser([FromBody] LoginUser loginUser)
        {
           
            var user = await _userManager.FindByEmailAsync(loginUser.Email!);
            if(user != null && await _userManager.CheckPasswordAsync(user, loginUser.Password!))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Email, user.Email!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                //add roles to token
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach(var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                var jwtToken = GetToken(authClaims);

                return Ok(new {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo 
                });
                //return Ok(user); 
            } else
            {
                return Unauthorized();
            }

        }

        //[HttpGet("Email")]
        //public IActionResult TestEmail()
        //{

        //    var message = new Message(new string[]

        //        {"tabotjunior07@gmail.com"}, "Testing 2......", "<h1>Subscribe to my channel</h1>");


        //     _emailService.SendEmail(message); 

        //    return StatusCode(StatusCodes.Status200OK, 
        //        new Response { Status = "Success", Message = "Email sent Successfully"});
        //}

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Email verified successfully"});
                }
            }

            return StatusCode(StatusCodes.Status500InternalServerError, 
                new Response { Status = "Error", Message = "This user does not exist"});
        }

        [HttpPost("AssignRoles")]
        public async Task<IActionResult> AssignRole(string email, string newRole)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return NotFound("User not Found");
            }

            var roleExist = await _roleManager.RoleExistsAsync(newRole);
            if (roleExist == false) return NotFound("Role does not exist");

            var currentRoles = await _userManager.GetRolesAsync(user);
            await _userManager.RemoveFromRolesAsync(user, currentRoles);
            await _userManager.AddToRoleAsync(user, newRole);
            return Ok("Role change was successful");

        }

        [HttpPost("forgotPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordLink = Url.Action(nameof(ResetPassword), "Auth",
                    new { token, email = user.Email }, Request.Scheme
                    );
                var message = new Message(new string[] { user.Email! }, "Forgot Password link", forgotPasswordLink!);
                _emailService.SendEmail(message);

                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = $"Password change request was sent to email {user.Email}" }
                        );
            }
            
            return StatusCode(StatusCodes.Status400BadRequest,
                        new Response { Status = "Error", Message = $"User with Email {user.Email} was not found" }
                        );

        }


        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };

            return Ok(new { model });

        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email!);
            if (user != null)
            {
                var result = await _userManager.ResetPasswordAsync(user, resetPassword.Token!, resetPassword.Password!);
                if(!result.Succeeded)
                {
                    foreach(var error in result.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(result);
                }
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password has been changed" });
               
            }
            return StatusCode(StatusCodes.Status400BadRequest,
            new Response { Status = "Error", Message = $"User with Email {user!.Email} was not found" }
                        );
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
    }

    
}
