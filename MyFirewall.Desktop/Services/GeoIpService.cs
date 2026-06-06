using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MyFirewall.Desktop.Services
{
    /// <summary>
    /// Provides geo-IP and reverse-DNS lookups with async caching.
    /// Fix #4: Uses ConcurrentDictionary so reads from the UI timer and writes from
    ///         background Tasks don't race each other.
    /// Fix #6: HttpClient has a 5-second timeout so a slow/absent ip-api.com never
    ///         leaks threadpool threads indefinitely.
    /// Fix #15: Implements IDisposable so HttpClient is properly cleaned up on shutdown.
    /// </summary>
    public class GeoIpService : IDisposable
    {
        private const string GeoApiBase = "http://ip-api.com/json/";
        private const int GeoMaxRetries = 3;

        // Fix #4: ConcurrentDictionary — safe for concurrent reads/writes from multiple threads.
        private readonly ConcurrentDictionary<string, string> _domainCache = new();
        private readonly ConcurrentDictionary<string, (string Display, string CountryCode)> _geoCache = new();

        private readonly SemaphoreSlim _geoSemaphore = new(1, 1);
        private DateTime _lastGeoCall = DateTime.MinValue;
        private readonly TimeSpan _geoApiThrottle = TimeSpan.FromSeconds(1.5);

        // Fix #6: 5-second timeout — prevents hung tasks when ip-api.com is unreachable.
        private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };

        private bool _disposed;

        public string GetCachedDomain(string ip)
        {
            if (_domainCache.TryGetValue(ip, out var domain)) return domain;

            // Reserve the slot immediately so concurrent calls don't spin up duplicate DNS lookups.
            if (!_domainCache.TryAdd(ip, "...")) return _domainCache.GetValueOrDefault(ip, "...");

            Task.Run(() =>
            {
                try { _domainCache[ip] = Dns.GetHostEntry(ip).HostName; }
                catch { _domainCache[ip] = "N/A"; }
            });
            return "...";
        }

        /// <summary>
        /// Returns cached geo display string (backward compatible).
        /// </summary>
        public string GetCachedGeo(string ip) => GetCachedGeoWithCode(ip).Display;

        /// <summary>
        /// Returns cached geo info including the country code for flag emoji rendering.
        /// </summary>
        public (string Display, string CountryCode) GetCachedGeoWithCode(string ip)
        {
            if (_geoCache.TryGetValue(ip, out var geo)) return geo;

            // Reserve the slot; only the first caller spawns the lookup Task.
            if (!_geoCache.TryAdd(ip, ("...", ""))) return _geoCache.GetValueOrDefault(ip, ("...", ""));

            Task.Run(async () => { _geoCache[ip] = await GeoIpLookupAsync(ip); });
            return ("...", "");
        }

        private async Task<(string Display, string CountryCode)> GeoIpLookupAsync(string ip)
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

                        // Strip "AS12345 " ASN prefix from org string for cleaner display
                        if (org.Length > 3 && org[0] == 'A' && org[1] == 'S')
                        {
                            int space = org.IndexOf(' ');
                            if (space > 0) org = org[(space + 1)..];
                        }

                        string display = string.IsNullOrEmpty(code) ? org : $"{org} · {code}";
                        return (display, code);
                    }
                    catch (TaskCanceledException) // Timeout hit
                    {
                        if (attempt == GeoMaxRetries - 1) return ("N/A", "");
                        await Task.Delay(delay);
                        delay *= 2;
                    }
                    catch
                    {
                        if (attempt == GeoMaxRetries - 1) return ("N/A", "");
                        await Task.Delay(delay);
                        delay *= 2;
                    }
                }
                return ("N/A", "");
            }
            finally { _geoSemaphore.Release(); }
        }

        // Fix #15: Dispose HttpClient to release socket handles.
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _http.Dispose();
            _geoSemaphore.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
