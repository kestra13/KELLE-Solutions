using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;

namespace KelleSolutions.Areas.Identity.Pages.Account.Password {
    
    class PasswordEncode {
        
        // Used for initial hashing of a password.  Return the hashed password 
        public static string EncodePassword(string password) {
            byte[] salt = RandomNumberGenerator.GetBytes(128 / 8);

            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8
            ));

            return hashed;
        } // end EncodePassword
    } // end PasswordEncode
} // end namespace