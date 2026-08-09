using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace MyFirewall.Desktop.Services
{
    public class TelemetryService
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        
        // Official GA4 Measurement Protocol Credentials
        private const string MeasurementId = "G-B387NLSSJX";
        private const string ApiSecret = "ch411kMtTRW7z_3XEUlmiw";
        private const string Endpoint = $"https://www.google-analytics.com/mp/collect?measurement_id={MeasurementId}&api_secret={ApiSecret}";
        
        private const string RegKeyPath = @"Software\MyFirewall";
        private string _clientId;

        public TelemetryService()
        {
            EnsureClientId();
        }

        public static bool IsTelemetryEnabled
        {
            get
            {
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(RegKeyPath);
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
                    using var key = Registry.CurrentUser.CreateSubKey(RegKeyPath);
                    key.SetValue("TelemetryEnabled", value ? 1 : 0, RegistryValueKind.DWord);
                }
                catch { }
            }
        }

        private void EnsureClientId()
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(RegKeyPath);
                _clientId = key?.GetValue("ClientId") as string;
                if (string.IsNullOrEmpty(_clientId))
                {
                    _clientId = Guid.NewGuid().ToString();
                    key?.SetValue("ClientId", _clientId);
                }
            }
            catch
            {
                _clientId = Guid.NewGuid().ToString();
            }
        }

        public async Task TrackEventAsync(string eventName, Dictionary<string, object> parameters = null)
        {
            if (!IsTelemetryEnabled) return;

            try
            {
                var payload = new
                {
                    client_id = _clientId,
                    events = new[]
                    {
                        new
                        {
                            name = eventName,
                            @params = parameters ?? new Dictionary<string, object>()
                        }
                    }
                };

                string json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                // Official GA4 Measurement Protocol call (/mp/collect)
                _ = _httpClient.PostAsync(Endpoint, content);
            }
            catch
            {
                // Fail silently so telemetry issues never crash the main application
            }
        }
    }
}
