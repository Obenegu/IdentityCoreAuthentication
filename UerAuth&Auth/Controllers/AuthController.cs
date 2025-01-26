using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UerAuth_Auth.Models.Auth.SignUp;
using UerAuth_Auth.Models;
using UerAuth_Auth.Models.Auth.Login;
using UserManagement.Service.Services;
using UserManagement.Service.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;

namespace UerAuth_Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IEmailService emailService, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            // user already exists
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email!);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "user Already exist!" }
                    );
            }

            // user does not exist
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Name,
            };


           if( await _roleManager.RoleExistsAsync(role))
            {
            var result = await _userManager.CreateAsync(user, registerUser.Password!);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response
                        {
                            Status = "Error",
                            Message = $"Failed to create user: {errors}"
                        });
                }

                  await _userManager.AddToRoleAsync(user, role);

                //Add token to verify email
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Auth", 
                    new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email!}, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);   


                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"User created & email sent to {user.Email} successfully" });
            } else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User role does not exist" });
            }

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
                    new Claim(ClaimTypes.Email, user.Email),
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

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user != null)
            {
                await _userManager.GeneratePasswordResetTokenAsync(user);
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
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var result = _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if(!result.IsCompletedSuccessfully)
                {
                    foreach(var error in result.Exception)
                    {
                        ModelState.AddModelError(error.Message);
                    }
                    return Ok(result);
                }
                return StatusCode(StatusCodes.Status200OK, 
                    new Response { Status = "Success", Message = $"Password has been changed" })
               
            }
            return StatusCode(StatusCodes.Status400BadRequest,
            new Response { Status = "Error", Message = $"User with Email {user.Email} was not found" }
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
