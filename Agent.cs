using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Relintio
{
    public class AgentConfig
    {
        public string LicenseKey { get; set; } = string.Empty;
        public string ApiUrl { get; set; } = "https://api.relintio.com/api";
        public int SyncIntervalSeconds { get; set; } = 60;
    }

    public class WafRule
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("pattern")]
        public string Pattern { get; set; } = string.Empty;

        [JsonPropertyName("condition")]
        public string Condition { get; set; } = string.Empty;

        [JsonPropertyName("score")]
        public int Score { get; set; }

        [JsonPropertyName("action")]
        public string Action { get; set; } = string.Empty;
    }

    public class SyncResponse
    {
        [JsonPropertyName("rules")]
        public List<WafRule> Rules { get; set; } = new();
    }

    public class WafResult
    {
        public int Score { get; set; }
        public string Action { get; set; } = "allow";
    }

    public class Agent
    {
        private readonly AgentConfig _config;
        private readonly HttpClient _httpClient;
        private List<WafRule> _rules = new();
        private readonly ReaderWriterLockSlim _lock = new();
        private CancellationTokenSource? _cts;

        public Agent(AgentConfig config)
        {
            _config = config;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _config.LicenseKey);
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public void StartSync()
        {
            _cts = new CancellationTokenSource();
            Task.Run(() => SyncLoop(_cts.Token));
        }

        public void StopSync()
        {
            _cts?.Cancel();
        }

        private async Task SyncLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await SyncRulesAsync();
                }
                catch
                {
                    // Fail-open
                }

                await Task.Delay(TimeSpan.FromSeconds(_config.SyncIntervalSeconds), token);
            }
        }

        public async Task SyncRulesAsync()
        {
            var url = $"{_config.ApiUrl.TrimEnd('/')}/rules/sync";
            var response = await _httpClient.GetAsync(url);
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var data = JsonSerializer.Deserialize<SyncResponse>(json);
                if (data != null)
                {
                    _lock.EnterWriteLock();
                    try
                    {
                        _rules = data.Rules;
                    }
                    finally
                    {
                        _lock.ExitWriteLock();
                    }
                }
            }
        }

        public WafResult CheckRequest(string ip, string userAgent, string path)
        {
            _lock.EnterReadLock();
            try
            {
                int score = 0;
                string action = "allow";

                foreach (var rule in _rules)
                {
                    bool matched = false;
                    switch (rule.Type.ToLower())
                    {
                        case "ip":
                            matched = MatchValue(ip, rule.Pattern, rule.Condition);
                            break;
                        case "user_agent":
                            matched = MatchValue(userAgent, rule.Pattern, rule.Condition);
                            break;
                        case "path":
                            matched = MatchValue(path, rule.Pattern, rule.Condition);
                            break;
                    }

                    if (matched)
                    {
                        score += rule.Score;
                        if (rule.Action == "block")
                        {
                            action = "block";
                        }
                        else if (rule.Action == "challenge" && action != "block")
                        {
                            action = "challenge";
                        }
                    }
                }

                if (score >= 100)
                {
                    action = "block";
                }
                else if (score >= 50 && action != "block")
                {
                    action = "challenge";
                }

                return new WafResult { Score = score, Action = action };
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        public void SendTelemetry(string ip, string userAgent, string path, WafResult result)
        {
            Task.Run(async () =>
            {
                try
                {
                    var url = $"{_config.ApiUrl.TrimEnd('/')}/telemetry/log";
                    var payload = new
                    {
                        ip = ip,
                        user_agent = userAgent,
                        path = path,
                        score = result.Score,
                        action = result.Action,
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    };

                    var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                    await _httpClient.PostAsync(url, content);
                }
                catch
                {
                    // Fail-open
                }
            });
        }

        private bool MatchValue(string value, string pattern, string condition)
        {
            if (string.IsNullOrEmpty(value) || string.IsNullOrEmpty(pattern))
                return false;

            return condition.ToLower() switch
            {
                "equals" => value == pattern,
                "contains" => value.Contains(pattern, StringComparison.OrdinalIgnoreCase),
                _ => value.Contains(pattern, StringComparison.OrdinalIgnoreCase)
            };
        }
    }
}
