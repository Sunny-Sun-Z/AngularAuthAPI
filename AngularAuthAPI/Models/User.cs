using System.ComponentModel.DataAnnotations;

namespace AngularAuthAPI.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        [EmailAddress(ErrorMessage ="Email format is not correct.")]
        public string Email { get; set; }
        public string Token { get; set; }
        public string Role { get; set; }
    }
}
