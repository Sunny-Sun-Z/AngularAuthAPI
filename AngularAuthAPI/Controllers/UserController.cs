using AngularAuthAPI.Context;
using AngularAuthAPI.Exceptions;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using AngularAuthAPI.Models.Dto;
using AngularAuthAPI.UtilityService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        private readonly IConfiguration _configuration;
     //   private readonly IEmailService _emailService;
        private readonly ILogger<UserController> _logger;
        public UserController(AppDbContext context, IConfiguration config,  ILogger<UserController> logger) //IEmailService emailService, temp comment out, gmail not working
        {
            _authContext = context;
            _configuration = config;
          //  _emailService = emailService;
           // _logger = logger;

        }
        [HttpPost("authentication")]
        public async Task<IActionResult> Authenticate([FromBody] UserLogin userObj)
        {
            if (userObj == null)
            {
                return BadRequest();
            }

            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName == userObj.UserName);

            if (user == null)
            {
                return NotFound(new { Message = "User Not Found!" });
            }
            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new { Message = $"Password invalid!" });
            }

            user.Token = CreateJwtToken(user);
            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokennExpireTime = DateTime.Now.AddDays(5);
            await _authContext.SaveChangesAsync();
            //return Ok(new { Message = "Login Sucessfully!" });

            // return Ok(new {User = user, Message = "Login Sucessfully!"} );

            return Ok(new
            {
                TokenApi = new TokenApiDto
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken
                },
                User = user,
                Message = "Login Sucessfully!"
            });
            //return Ok( new TokenApiDto
            //    {
            //        AccessToken = newAccessToken,
            //        RefreshToken = newRefreshToken
            //    }
            //);

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
                //new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
                new Claim(ClaimTypes.Name, $"{user.UserName}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.UtcNow.AddSeconds(10), //DateTime.UtcNow.AddDays(1), //
                SigningCredentials = credentials,
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        private string CreateRefreshToken() // just a random data
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);

            var tokenInUser = _authContext.Users
                .Any(a=>a.RefreshToken == refreshToken);

            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }



        [Authorize]
        [HttpGet("GetAllUsers")]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok( await _authContext.Users.ToListAsync());
        }

        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryveryveryveryveryverysecret.....");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false,
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("This is Invalid Token");
            return principal;
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApito)
        {
            if (tokenApito == null)
                return BadRequest("Invalid Client Request");

            string accessToken = tokenApito.AccessToken;
            string refreshToken = tokenApito.RefreshToken;
            var principle = GetPrincipleFromExpiredToken(accessToken);    
            var username = principle.Identity.Name;
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName == username);

            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokennExpireTime <= DateTime.Now)
                return BadRequest("Invalid Request");

            var newAccessToken = CreateJwtToken(user);
            var newRefreshToken = CreateRefreshToken();

            user.RefreshToken = newRefreshToken;
           // user.Token = newAccessToken;
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
               {
                   AccessToken = newAccessToken,
                   RefreshToken = newRefreshToken
               });
        }

        [HttpPost("send-reset-email/{email}")]
        public async Task<IActionResult> SendEmail(string email)
        {
            var user = await _authContext.Users.FirstOrDefaultAsync(u=>u.Email==email);
            if (user is null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "email does not Exists."
                });
            }

            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var emailToken = Convert.ToBase64String(tokenBytes);
            user.ResetPasswordToken = emailToken;
            user.RefreshTokennExpireTime = DateTime.Now.AddMinutes(15);
            string from = _configuration["EmailSettings:From"];
            var emailModel = new EmailModel(email, "Reset Password", EmailBody.EamilStringBody(email, emailToken));
           // _emailService.SendEmail(emailModel);
            _authContext.Entry(user).State = EntityState.Modified;
            await _authContext.SaveChangesAsync();

            _logger.LogInformation("just first test");

            return Ok(new
            {
                StatusCode = 200,
                Message = "Email Sent!"
            });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassord(ResetPasswordDto resetPasswordDto)
        {
            var newToken = resetPasswordDto.EmailToken.Replace(" ", "+").Replace("\\","").Replace("\"", "");

            var user = await _authContext.Users.AsNoTracking().FirstOrDefaultAsync(u=>u.Email==resetPasswordDto.Email);
            if (user is null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "email does not Exists."
                });
            }
            var tokenCode = user.ResetPasswordToken;
            DateTime emailTokenExpiry = user.RefreshTokennExpireTime;
            if(tokenCode != newToken || emailTokenExpiry< DateTime.Now)
            {
                return BadRequest(
                    new
                    {
                        StatusCode = 400,
                        Message = "Invalid Reset link"
                    });
            }

            user.Password = PasswordHasher.HashPassword(resetPasswordDto.NewPassword);
            _authContext.Entry(user).State = EntityState.Modified;
            await _authContext.SaveChangesAsync();

            return Ok(new
            {
                StatusCode = 200,
                Message = "Password Reset Successfully!"
            });
        }

        //[HttpGet]
        //public Task<ActionResult<User>> GetUserById(int id)
        //{
        //    try
        //    {

        //    }

        //    catch (Exception ex)
        //    {
        //        var exception = new AppExceptionHandler(_logger);
        //        //return exception.

        //    }
        //}
    }
}
