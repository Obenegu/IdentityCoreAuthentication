using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.Security.Claims;
using UerAuth_Auth.Models;
using UerAuth_Auth.Models.Dto;
using User.Management.Data.Data;

namespace UerAuth_Auth.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class TodoAdminController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public TodoAdminController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet("all-tasks")]
        public async Task<IActionResult> GetAllUsersTasks()
        {
            var todo = await _context.Todos
                .Select(t => new ToDoDto()
                {
                    Title = t.Title,
                    Description = t.Description,
                    Id = t.Id,
                    ApplicationUserId = t.ApplicationUserId,
                    isCompleted = t.isCompleted,
                    UserName = _context.Users
                        .Where(u => u.Id == t.ApplicationUserId)
                        .Select(u => u.UserName)
                        .FirstOrDefault()
                }).ToListAsync();

            return Ok(todo);
        }

        [HttpPost]
        public async Task<IActionResult> AssignTaskToUser(string email, ToDoDto task)
        {

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

            if (user == null)
            {
                return BadRequest("User with the specified email not found.");
            }

            await _context.AddAsync(new ToDo()
            {
                Title = task.Title,
                Description = task.Description,
                ApplicationUserId = user.Id,
                isCompleted = task.isCompleted
            });

            await _context.SaveChangesAsync();
            return Ok(task);
        }
    }
}
