using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserManagement.Service.Models.Auth.User
{
    public class LoginResponse
    {
        public TokenTypes AccessToken { get; set; }
        public TokenTypes RefreshToken { get; set; }
    }
}
