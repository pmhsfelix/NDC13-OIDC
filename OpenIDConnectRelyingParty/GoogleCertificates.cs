using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using Newtonsoft.Json.Linq;

namespace OpenIDConnectRelyingParty
{
    public static class GoogleCertificates
    {
        public static async Task<IEnumerable<KeyValuePair<string,X509Certificate2>>> GetCertificates()
        {
            using(var client = new HttpClient())
            {
                var resp = await client.GetAsync("https://www.googleapis.com/oauth2/v1/certs");
                resp.EnsureSuccessStatusCode();
                var json = await resp.Content.ReadAsAsync<JObject>();
                return json.Properties().ToDictionary(p => p.Name, p => CreateCertificateFrom(p.Value.ToObject<string>()));
            }
        }

        private static X509Certificate2 CreateCertificateFrom(string value)
        {
            value = value.Replace("-----BEGIN CERTIFICATE-----", "");
            value = value.Replace("-----END CERTIFICATE-----", "");
            value = value.Replace("\n", "");
            return new X509Certificate2(Convert.FromBase64String(value));
        }
    }

}