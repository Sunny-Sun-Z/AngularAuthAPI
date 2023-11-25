namespace AngularAuthAPI.Models.Dto
{
    public class TokenApiDto
    {
        public string AccessToken { get; set; } = string.Empty;  // jwt token, or just the orig token
        public string RefreshToken { get; set; } = string.Empty;   
    }
}
