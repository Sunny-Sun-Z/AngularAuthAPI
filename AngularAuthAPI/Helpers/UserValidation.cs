using AngularAuthAPI.Context;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Helpers
{
    public class UserValidation
    {

        public static  Task<bool> CheckUserNameExistsAsyn(string userName, AppDbContext _authContext)
        
           => _authContext.Users.AnyAsync(user => user.UserName.ToUpper() == userName.ToUpper());

        public static Task<bool> CheckEmailExistsAsyn(string email, AppDbContext _authContext)

           => _authContext.Users.AnyAsync(user => user.Email.ToUpper() == email.ToUpper());

        public static string CheckPasswordLengthAsyn(string password, AppDbContext _authContext)
        {
            StringBuilder sb = new StringBuilder();

            if (password.Length < 6)
                sb.Append("Password min size is 6." + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]")
            && Regex.IsMatch(password, "[A-z]")
            && Regex.IsMatch(password, "[0-9]")))
            {
                sb.Append("Password should be Alphanumberic"+Environment.NewLine);
            }
            if (!Regex.IsMatch(password, "[<,>,@, &, #, $,+, \\, [,\\], {, }]"))
            {
                sb.Append("Password should contain special chars."+Environment.NewLine);
            }
            return sb.ToString();
        }
    }
}
