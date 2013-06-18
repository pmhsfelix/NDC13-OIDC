using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Facts
{
    public class JwtFacts
    {
        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        public static long ToEpochTime(DateTime dt)
        {
            return (long)(dt - UnixEpoch).TotalSeconds;
        }

        [Fact]
        public void Can_create_and_validate_token()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var symmetricKey = GetRandomBytes(256 / 8);

            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                        {
                            new Claim(ClaimTypes.Name, "Pedro"),
                            new Claim(ClaimTypes.NameIdentifier, "pmhsfelix@gmail.com"), 
                            new Claim(ClaimTypes.Role, "Author"),
                            new Claim("iat", ToEpochTime(now).ToString(),ClaimValueTypes.Integer), 
                            
                        }),
                
                TokenIssuerName = "self",
                AppliesToAddress = "http://www.example.com",
                Lifetime = new Lifetime(now, now.AddMinutes(2)),
                SigningCredentials = new SigningCredentials(
                    new InMemorySymmetricSecurityKey(symmetricKey),
                    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                    "http://www.w3.org/2001/04/xmlenc#sha256"),
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);

            var tokenString = tokenHandler.WriteToken(token);
            Console.WriteLine(tokenString);

            var validationParameters = new TokenValidationParameters()
            {
                AllowedAudience = "http://www.example.com",
                SigningToken = new BinarySecretSecurityToken(symmetricKey),
                ValidIssuer = "self"
            };
            var principal = tokenHandler.ValidateToken(tokenString, validationParameters);
            Assert.True(principal.Identities.First().Claims
                .Any(c => c.Type == ClaimTypes.Name && c.Value == "Pedro"));
            Assert.True(principal.Identities.First().Claims
                .Any(c => c.Type == ClaimTypes.Role && c.Value == "Author"));
        }

        private static byte[] GetRandomBytes(int byteLen)
        {
            using(var crg = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[byteLen];
                crg.GetBytes(bytes);
                return bytes;
            }
        }
    }
}
