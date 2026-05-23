using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MyFirewall.Desktop.Services
{
    public class GeoIpService
    {
        private const string GeoApiBase = "http://ip-api.com/json/";
        private const int GeoMaxRetries = 3;
        
        private readonly Dictionary<string, string> _domainCache = new();
        private readonly Dictionary<string, string> _geoCache = new();
        private readonly SemaphoreSlim _geoSemaphore = new(1, 1);
        private DateTime _lastGeoCall = DateTime.MinValue;
        private readonly TimeSpan _geoApiThrottle = TimeSpan.FromSeconds(1.5);
        private readonly HttpClient _http = new();

        public string GetCachedDomain(string ip)
        {
            if (_domainCache.TryGetValue(ip, out var domain)) return domain;
            _domainCache[ip] = "...";
            Task.Run(() =>
            {
                try { _domainCache[ip] = Dns.GetHostEntry(ip).HostName; }
                catch { _domainCache[ip] = "N/A"; }
            });
            return "...";
        }

        public string GetCachedGeo(string ip)
        {
            if (_geoCache.TryGetValue(ip, out var geo)) return geo;
            _geoCache[ip] = "...";
            Task.Run(async () => { _geoCache[ip] = await GeoIpLookupAsync(ip); });
            return "...";
        }

        private async Task<string> GeoIpLookupAsync(string ip)
        {
            await _geoSemaphore.WaitAsync();
            try
            {
                var wait = _geoApiThrottle - (DateTime.UtcNow - _lastGeoCall);
                if (wait > TimeSpan.Zero) await Task.Delay(wait);
                _lastGeoCall = DateTime.UtcNow;

                int delay = 500;
                for (int attempt = 0; attempt < GeoMaxRetries; attempt++)
                {
                    try
                    {
                        string url = $"{GeoApiBase}{Uri.EscapeDataString(ip)}?fields=status,org,countryCode";
                        string json = await _http.GetStringAsync(url);

                        using var doc = JsonDocument.Parse(json);
                        var root = doc.RootElement;

                        if (!root.TryGetProperty("status", out var status) || status.GetString() != "success")
                        {
                            await Task.Delay(delay);
                            delay *= 2;
                            continue;
                        }

                        string org = root.TryGetProperty("org", out var o) ? o.GetString() ?? "" : "";
                        string code = root.TryGetProperty("countryCode", out var c) ? c.GetString() ?? "" : "";

                        if (org.Length > 3 && org[0] == 'A' && org[1] == 'S')
                        {
                            int space = org.IndexOf(' ');
                            if (space > 0) org = org[(space + 1)..];
                        }

                        return string.IsNullOrEmpty(code) ? org : $"{org} · {code}";
                    }
                    catch
                    {
                        if (attempt == GeoMaxRetries - 1) return "N/A";
                        await Task.Delay(delay);
                        delay *= 2;
                    }
                }
                return "N/A";
            }
            finally { _geoSemaphore.Release(); }
        }
    }
}
