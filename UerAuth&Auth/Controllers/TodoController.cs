using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using UerAuth_Auth.Models;
using UerAuth_Auth.Models.Dto;
using User.Management.Data.Data;

namespace UerAuth_Auth.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class TodoController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        public TodoController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpPost]
        public async Task<IActionResult> CreateTask(ToDoDto task)
        {
            var userEmail = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(userEmail))
            {
                return Unauthorized("Session expired");
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);
            

            if (task != null)
            {
               var newTask = await _context.AddAsync(new ToDo()
                {
                    Title = task.Title,
                    Description = task.Description,
                    Id = task.Id,
                    ApplicationUserId = user!.Id,
                    isCompleted = task.isCompleted
                });

                await _context.SaveChangesAsync();
                return Ok(newTask);
            }
            else
            {
                return BadRequest();
            }

        }

        
        [HttpGet]
        public async Task<IActionResult> GetAllTasks() 
        {

            var userEmail = User.FindFirst(ClaimTypes.Email)?.Value;
            if (userEmail == null)
            {
                return BadRequest("User Email not found");
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);
            if (user == null)
            {
                return NotFound("User not found");
            }

            var todo = await _context.Todos
                .Where(t => t.ApplicationUserId == user.Id)
                .Select(t => new ToDoDto() 
            { 
                Title=t.Title, 
                Description = t.Description, 
                Id = t.Id,
                isCompleted = t.isCompleted
            }).ToListAsync();

            return Ok(todo);

            //return Ok(await Task.FromResult(todo));
        }

        [HttpPut("{Id}")]
        public async Task<IActionResult> UpdateTodo([FromBody] ToDoDto updatedTask, int Id)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest();
            }

            var task = await _context.Todos.FindAsync(Id);

            if (task == null)
            {
                return BadRequest();
            }


                task.Title = updatedTask.Title;
                task.Description = updatedTask.Description;
                task.isCompleted = updatedTask.isCompleted;

            await _context.SaveChangesAsync();

            return Ok(task);
        }

        [HttpDelete("{Id}")]
        public async Task<IActionResult> DeleteTask(int Id)
        {
            var task = await  _context.Todos.FindAsync(Id);
            if (task == null) { return NotFound(); }
            _context.Todos.Remove(task);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        [HttpGet("search")]
        public async Task<IActionResult> SearchTasks( string? title, string? description)
        {
            var query = _context.Todos.AsQueryable(); 
            if (!string.IsNullOrEmpty(title)) 
            { 
                query = query.Where(t => EF.Functions.Like(t.Title, $"%{title}%")); 
            }
            

            if (!string.IsNullOrEmpty(description))
            {
                query = query.Where(t => EF.Functions.Like(t.Description, $"%{description}%"));
            }

            var result = await query
                .Select(t => new ToDo
                {
                    Title = t.Title,
                    Description = t.Description,
                    Id = t.Id,
                    ApplicationUserId = t.ApplicationUserId,
                    isCompleted = t.isCompleted
                }).ToListAsync();

            return Ok(result);
        }

       
    }
}
