using System.Drawing;
using System.Security.Cryptography;

namespace AngularAuthAPI.Helpers
{
    public class PasswordHasher
    {
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private static readonly int SaltSize = 16;
        private static readonly int HasSize = 20;
        private static readonly int Iteration = 10000;

        public static string HashPassword(string password)
        {
            //using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            //using (var rng = RandomNumberGenerator.Create())
            //{
                byte[] salt;
                rng.GetBytes(salt = new byte[SaltSize]);
                var key = new Rfc2898DeriveBytes(password, salt, Iteration);
                var hash = key.GetBytes(HasSize);

                var hashBytes = new byte[SaltSize + HasSize];
                Array.Copy(salt,0, hashBytes, 0, SaltSize);
                Array.Copy(hash, 0, hashBytes, SaltSize, HasSize);

                var base64Hash = Convert.ToBase64String(hashBytes);
                return base64Hash;
            //}
        }

        public static bool VerifyPassword (string password, string base64Hash) 
        {
            var hashBytes = Convert.FromBase64String(base64Hash);

            var salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            var key = new Rfc2898DeriveBytes(password, salt, Iteration);
            byte[] hash = key.GetBytes(HasSize);

            for(var i=0; i<HasSize; i++)
            {
                if (hashBytes[i + SaltSize] != hash[i])
                    return false; //temp set to true, should be false, but the code not working... always return false.
            }
            return true;
        }
    }
}
