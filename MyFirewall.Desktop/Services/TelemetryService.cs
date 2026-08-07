using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace MyFirewall.Desktop.Services
{
    public class TelemetryService
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        private const string MeasurementId = "G-3Y256NPRT9";
        
        // Use a persistent GUID for the user to track sessions accurately
        // For testing, we'll generate a random one per app launch
        private readonly string _clientId = Guid.NewGuid().ToString();

        public static bool IsTelemetryEnabled
        {
            get
            {
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(@"Software\MyFirewall");
                    if (key != null)
                    {
                        var val = key.GetValue("TelemetryEnabled");
                        if (val is int intVal) return intVal == 1;
                    }
                    return true; // Default to true
                }
                catch { return true; }
            }
            set
            {
                try
                {
                    using var key = Registry.CurrentUser.CreateSubKey(@"Software\MyFirewall");
                    key.SetValue("TelemetryEnabled", value ? 1 : 0, RegistryValueKind.DWord);
                }
                catch { }
            }
        }

        public async Task TrackEventAsync(string eventName)
        {
            if (!IsTelemetryEnabled) return;

            try
            {
                // v=2  : GA4 Protocol Version
                // tid  : Measurement ID
                // cid  : Client ID (anonymous identifier for the user/device)
                // en   : Event Name
                var url = $"https://www.google-analytics.com/g/collect?v=2&tid={MeasurementId}&cid={_clientId}&en={Uri.EscapeDataString(eventName)}";
                
                var request = new HttpRequestMessage(HttpMethod.Post, url);
                
                // Optional: Provide a user agent so GA4 knows it's a desktop app
                request.Headers.UserAgent.ParseAdd("MyFirewallApp/1.0 (Windows NT 10.0; Win64; x64)");
                
                // Fire and forget, don't await the response in the main thread
                _ = _httpClient.SendAsync(request);
            }
            catch
            {
                // Fail silently so telemetry issues never crash the main application
            }
        }
    }
}
