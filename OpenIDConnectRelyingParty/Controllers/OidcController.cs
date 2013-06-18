using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using ClaimTypes = System.IdentityModel.Claims.ClaimTypes;

namespace OpenIDConnectRelyingParty.Controllers
{
    public class OidcController : Controller
    {
        /* OAuth client details, REPLACE by your own */
        private const string ClientId = "55...gr.apps.googleusercontent.com";
        private const string ClientSecret = "ML...kv";
        private const string RedirectUri = "https://www.example.net:4430/Oidc/callback";

        private const string Scope = "openid email https://www.googleapis.com/auth/tasks.readonly";
        
        public ActionResult Index()
        {
            var state = GetState();
            var uri =
                string.Format(
                    @"https://accounts.google.com/o/oauth2/auth?client_id={0}&response_type=code&scope={1}&redirect_uri={2}&state={3}",
                    HttpUtility.UrlEncode(ClientId), 
                    HttpUtility.UrlEncode(Scope), 
                    HttpUtility.UrlEncode(RedirectUri),
                    HttpUtility.UrlEncode(state)
                    );
            return new RedirectResult(uri);
        }

        public async Task<ActionResult> Callback(string code, string state)
        {
            CheckState(state);

            using (var client = new HttpClient())
            {
                var resp = await client.PostAsync("https://accounts.google.com/o/oauth2/token",
                                 new FormUrlEncodedContent(new Dictionary<string, string>
                                                               {
                                                                   {"code", code},
                                                                   {"redirect_uri", RedirectUri},
                                                                   {"grant_type", "authorization_code"},
                                                                   {"client_id", ClientId},
                                                                   {"client_secret", ClientSecret}
                                                               }));
                resp.EnsureSuccessStatusCode();
                var tokenResp = await resp.Content.ReadAsAsync<TokenResponse>();

                var certs = await GoogleCertificates.GetCertificates();

                var tokenHandler = new JwtSecurityTokenHandler
                {
                    CertificateValidator = new GoogleCertificateValidator(certs.ToDictionary(t => t.Value.GetCertHashString(), t => t.Value))
                };

                var validationParameters = new TokenValidationParameters()
                {
                    AllowedAudience = ClientId,
                    ValidIssuer = "accounts.google.com",
                    SigningTokens = certs.Select(p => new X509SecurityToken(p.Value))
                };
                var principal = tokenHandler.ValidateToken(tokenResp.id_token, validationParameters);

                var jwt = new JwtSecurityToken(tokenResp.id_token);

                var viewModel = new ViewModel
                                    {
                                        JwtHeader = jwt.Header,
                                        JwtPayload = jwt.Payload,
                                        Principal = principal
                                    };

                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenResp.access_token);
                resp = await client.GetAsync("https://www.googleapis.com/tasks/v1/users/@me/lists");
                resp.EnsureSuccessStatusCode();
                var taskLists = await resp.Content.ReadAsAsync<TaskLists>();
                foreach(var list in taskLists.items)
                {
                    resp = await client.GetAsync(string.Format("https://www.googleapis.com/tasks/v1/lists/{0}/tasks",list.id));
                    resp.EnsureSuccessStatusCode();
                    var taskList = await resp.Content.ReadAsAsync<TaskList>();
                    viewModel.Tasks.AddRange(taskList.items.Select(item => item.title));
                }
                
                return View(viewModel);
            }
        }

        private string GetState()
        {
            return "should use a robust CSRF method and not a literal string";
        }

        private void CheckState(string state)
        {
            // should enforce valid state
        }
    }

    public class ViewModel
    {
        public JwtHeader JwtHeader { get; set; }
        public JwtPayload JwtPayload { get; set; }
        public ClaimsPrincipal Principal { get; set; }
        public List<string> Tasks { get; set; }

        public ViewModel()
        {
            Tasks = new List<string>();
        }
    }

    
    public class GoogleCertificateValidator : X509CertificateValidator
    {
        private readonly Dictionary<string, X509Certificate2> _certs;

        public GoogleCertificateValidator(Dictionary<string,X509Certificate2> certs)
        {
            _certs = certs;
        }
        public override void Validate(X509Certificate2 certificate)
        {
            if(!_certs.ContainsKey(certificate.GetCertHashString()))
            {
                throw new SecurityTokenException("invalid certificate");
            }
        }
    }

    class TokenResponse
    {
        public string access_token { get; set; }
        public string id_token { get; set; }
    }

    class TaskLists
    {
        public string kind { get; set; }
        public TaskListsItem[] items { get; set; }
    }

    class TaskListsItem
    {
        public string id { get; set; }
        public string title { get; set; }
        public string selfLink { get; set; }
    }

    class TaskList
    {
        public string kind { get; set; }
        public TaskListItem[] items { get; set; }
    }

    class TaskListItem
    {
        public string title { get; set; }
    }
}
