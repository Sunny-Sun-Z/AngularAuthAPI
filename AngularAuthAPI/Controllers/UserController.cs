using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext context)
        {
            _authContext = context;
        }
        [HttpPost("authentication")]
        public async Task<IActionResult> Authenticate([FromBody] Models.User userObj)
        {
            if(userObj == null)
            {
                return BadRequest();
            }
            var user = await _authContext.Users.FirstOrDefaultAsync(u=> u.UserName == userObj.UserName && u.Password==userObj.Password);
            if(user == null)
            {
                return NotFound(new {Message= "User Not Found!"});
            }
            else
            {
                return Ok(new {Message="Login Sucessfully!"});
            }
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if(userObj == null) 
                return BadRequest();

            //if(string.IsNullOrEmpty(userObj.UserName)) { }
           
            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new {Message= "User Registered!"});
        }

        
      
    }
}
