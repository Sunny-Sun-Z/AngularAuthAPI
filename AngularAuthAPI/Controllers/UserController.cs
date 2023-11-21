using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

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
            
            var user = await _authContext.Users.FirstOrDefaultAsync(u=> u.UserName == userObj.UserName);
            
            if(user == null)
            {
                return NotFound(new {Message= "User Not Found!"});
            }
            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new { Message = $"Password invalid!" });
            }
            //return Ok(new { Message = "Login Sucessfully!" });
            user.Token = CreateJwtToken(user);
            return Ok(new { Token= user.Token, Message= "Login Sucessfully!" });
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if(userObj == null) 
                return BadRequest(new {Message="user is null!"});
            // check user exists

            if( await UserValidation.CheckUserNameExistsAsyn(userObj.UserName, _authContext))
            {
                return BadRequest(new { Message = $"User name: {userObj.UserName} already exists!" });
            }

            // check email, 
            if (await UserValidation.CheckEmailExistsAsyn(userObj.Email, _authContext))
                return BadRequest(new { Message = $"Email address: {userObj.Email} already exists!" });

            //if (!ModelState.IsValid)
            //{
            //    if(userObj.Email != null)
            //    {
            //        if(!new EmailAddressAttribute().IsValid(userObj.Email))
            //        {
            //            return BadRequest(new { Message = $"Email address: {userObj.Email} does not have correct email format!" });
            //        }
            //    }
            //}

            // check password length, temp comment out to easy passord creation and remember
            //string passwordError = UserValidation.CheckPasswordLengthAsyn(userObj.Password, _authContext);
            //if (!string.IsNullOrEmpty(passwordError))
            //    return BadRequest(new { Message = passwordError });

            

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
          
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new {Message= "User Registered!"});
        }

        private string CreateJwtToken(User user)
        {
            // header,  signature
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryveryveryveryveryverysecret.....");

            // payload
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = credentials,
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        [HttpGet("GetAllUsers")]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok( await _authContext.Users.ToListAsync());
        }


    }
}
