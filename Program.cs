using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AnyDeskInspector
{
    public class GeoIpResponse
    {
        [JsonPropertyName("status")] public string? Status { get; set; }
        [JsonPropertyName("country")] public string? Country { get; set; }
        [JsonPropertyName("regionName")] public string? RegionName { get; set; }
        [JsonPropertyName("city")] public string? City { get; set; }
        [JsonPropertyName("isp")] public string? Isp { get; set; }
        [JsonPropertyName("org")] public string? Org { get; set; }
        [JsonPropertyName("as")] public string? As { get; set; }
        [JsonPropertyName("lat")] public double? Lat { get; set; }
        [JsonPropertyName("lon")] public double? Lon { get; set; }
        [JsonPropertyName("timezone")] public string? Timezone { get; set; }
        [JsonPropertyName("message")] public string? Message { get; set; }
    }

    public class LogEntry
    {
        public DateTime? Timestamp { get; set; }
        public string SourceFile { get; set; } = string.Empty;
        public int LineNumber { get; set; }
        public string EventType { get; set; } = "Unknown";
        public string AnyDeskId { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string RawLine { get; set; } = string.Empty;
        public GeoIpResponse? GeoData { get; set; }
    }

    public class FileEvidence
    {
        public string FilePath { get; set; } = string.Empty;
        public long FileSizeBytes { get; set; }
        public DateTime LastModified { get; set; }
        public string Sha256Hash { get; set; } = string.Empty;
    }

    internal class Program
    {
        private static readonly HttpClient httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
        
        // Опциональные настройки Telegram (можно задать в config.json или через CLI)
        private static string? TelegramBotToken = null;
        private static string? TelegramChatId = null;

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            LoadConfig();

            bool isSilent = args.Contains("--silent");
            bool sendTg = args.Contains("--telegram");

            if (!isSilent)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("==========================================================================");
                Console.WriteLine("     AnyDesk Forensic & Incident Response Suite (Forensics + Alerting)    ");
                Console.WriteLine("==========================================================================\n");
                Console.ResetColor();
            }

            // 1. Поиск и сбор улик (Файлы логов + SHA-256)
            PrintStep("[1/5] Сбор цифровых доказательств и вычисление SHA-256 хэшей...", isSilent);
            var evidenceFiles = CollectEvidenceFiles();
            foreach (var ev in evidenceFiles)
            {
                if (!isSilent)
                    Console.WriteLine($"   📁 {Path.GetFileName(ev.FilePath)} ({ev.FileSizeBytes} байт) -> SHA256: {ev.Sha256Hash.Substring(0, 16)}...");
            }

            // 2. Парсинг сессий, таймлайна и IP
            PrintStep("\n[2/5] Глубокий парсинг логов и построение криминалистического таймлайна...", isSilent);
            var timeline = ParseLogsDetailed(evidenceFiles);
            if (!isSilent)
                Console.WriteLine($"   [+] Обнаружено {timeline.Count} значимых событий в логах.");

            // 3. Анализ активных подключений через Win32 API
            PrintStep("\n[3/5] Проверка активных TCP сокетов AnyDesk.exe...", isSilent);
            var activeConns = GetActiveAnyDeskConnections();
            if (activeConns.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                if (!isSilent) Console.WriteLine($"   [!] ОБНАРУЖЕНО {activeConns.Count} АКТИВНЫХ СОЕДИНЕНИЙ В РЕАЛЬНОМ ВРЕМЕНИ!");
                Console.ResetColor();
                timeline.InsertRange(0, activeConns);
            }
            else if (!isSilent)
            {
                Console.WriteLine("   [-] Активных сетевых сессий в данный момент нет.");
            }

            // 4. GeoIP Резолвинг уникальных адресов
            var uniqueIps = timeline.Where(t => !string.IsNullOrEmpty(t.IpAddress) && !IsPrivateIp(t.IpAddress))
                                    .Select(t => t.IpAddress)
                                    .Distinct()
                                    .ToList();

            PrintStep($"\n[4/5] Определение геолокации и провайдеров для {uniqueIps.Count} внешних IP...", isSilent);
            var geoCache = new Dictionary<string, GeoIpResponse>();

            foreach (var ip in uniqueIps)
            {
                var geo = await FetchGeoIpAsync(ip);
                if (geo != null) geoCache[ip] = geo;
                
                if (!isSilent)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write($"   -> IP: {ip,-15} ");
                    Console.ResetColor();
                    if (geo?.Status == "success")
                    {
                        Console.WriteLine($"| {geo.Country}, {geo.City} | ISP: {geo.Isp} | Org: {geo.Org ?? geo.As}");
                    }
                    else
                    {
                        Console.WriteLine($"| GeoIP: {geo?.Message ?? "N/A"}");
                    }
                }
                await Task.Delay(300);
            }

            // Прикрепляем GeoData к событиям таймлайна
            foreach (var item in timeline)
            {
                if (!string.IsNullOrEmpty(item.IpAddress) && geoCache.TryGetValue(item.IpAddress, out var g))
                {
                    item.GeoData = g;
                }
            }

            // 5. Генерация отчетов и форензик пакета
            PrintStep("\n[5/5] Генерация отчетов, карты, таймлайна и заявления в полицию...", isSilent);
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string htmlReportPath = Path.Combine(baseDir, $"Forensic_Report_{timestamp}.html");
            string policeReportPath = Path.Combine(baseDir, $"Police_Statement_{timestamp}.txt");
            string jsonReportPath = Path.Combine(baseDir, $"Forensic_Data_{timestamp}.json");

            GenerateForensicHtmlReport(htmlReportPath, timeline, evidenceFiles);
            GeneratePoliceStatement(policeReportPath, timeline, evidenceFiles);
            GenerateJsonReport(jsonReportPath, timeline, evidenceFiles);

            if (!isSilent)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\n==========================================================================");
                Console.WriteLine("                 РЕЗУЛЬТАТЫ РАССЛЕДОВАНИЯ СОХРАНЕНЫ                       ");
                Console.WriteLine("==========================================================================");
                Console.ResetColor();
                Console.WriteLine($" [1] 📊 Интерактивный HTML-отчет с картой: {htmlReportPath}");
                Console.WriteLine($" [2] 📄 Готовое заявление в МВД / Банк:     {policeReportPath}");
                Console.WriteLine($" [3] 💾 JSON данные для экспертизы:        {jsonReportPath}");
            }

            // Отправка в Telegram (если настроено или передан флаг)
            if (sendTg || !string.IsNullOrEmpty(TelegramBotToken))
            {
                await SendTelegramAlertAsync(timeline, evidenceFiles);
            }

            // Открытие HTML отчета в браузере
            if (!isSilent)
            {
                try { Process.Start(new ProcessStartInfo(htmlReportPath) { UseShellExecute = true }); } catch { }
                Console.WriteLine("\nНажмите любую клавишу для выхода...");
                Console.ReadKey();
            }
        }

        private static void PrintStep(string msg, bool silent)
        {
            if (silent) return;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(msg);
            Console.ResetColor();
        }

        #region Telegram Alerts
        private static void LoadConfig()
        {
            string cfgPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.json");
            if (File.Exists(cfgPath))
            {
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(cfgPath));
                    if (doc.RootElement.TryGetProperty("TelegramBotToken", out var token))
                        TelegramBotToken = token.GetString();
                    if (doc.RootElement.TryGetProperty("TelegramChatId", out var chat))
                        TelegramChatId = chat.GetString();
                }
                catch { }
            }
        }

        private static async Task SendTelegramAlertAsync(List<LogEntry> timeline, List<FileEvidence> evidence)
        {
            if (string.IsNullOrEmpty(TelegramBotToken) || string.IsNullOrEmpty(TelegramChatId))
            {
                Console.WriteLine("[-] Telegram не настроен (укажите TelegramBotToken и TelegramChatId в config.json).");
                return;
            }

            var latestActive = timeline.FirstOrDefault(t => t.EventType.Contains("Активное"));
            var suspiciousIps = timeline.Where(t => t.GeoData?.Status == "success").Select(t => t.IpAddress).Distinct().Take(3).ToList();

            var sb = new StringBuilder();
            sb.AppendLine("🚨 <b>ВНИМАНИЕ! ЗАФИКСИРОВАНА СЕССИЯ ANYDESK</b>");
            sb.AppendLine($"📅 Время: <code>{DateTime.Now:yyyy-MM-dd HH:mm:ss}</code>");
            sb.AppendLine($"💻 Компьютер: <code>{Environment.MachineName} ({Environment.UserName})</code>\n");

            if (latestActive != null)
            {
                sb.AppendLine("🔴 <b>Активное подключение:</b>");
                sb.AppendLine($"• IP: <code>{latestActive.IpAddress}:{latestActive.GeoData?.City}</code>");
                if (latestActive.GeoData != null)
                {
                    sb.AppendLine($"• Локация: {latestActive.GeoData.Country}, {latestActive.GeoData.City}");
                    sb.AppendLine($"• Провайдер: {latestActive.GeoData.Isp}");
                }
            }

            sb.AppendLine("\n📋 <b>Обнаруженные внешние IP в логах:</b>");
            foreach (var ip in suspiciousIps)
            {
                var entry = timeline.FirstOrDefault(t => t.IpAddress == ip);
                var geo = entry?.GeoData;
                sb.AppendLine($"• <code>{ip}</code> ({geo?.Country ?? "?"}, {geo?.City ?? "?"} - {geo?.Isp ?? "?"})");
            }

            try
            {
                string url = $"https://api.telegram.org/bot{TelegramBotToken}/sendMessage";
                var payload = new { chat_id = TelegramChatId, text = sb.ToString(), parse_mode = "HTML" };
                var json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var res = await httpClient.PostAsync(url, content);
                if (res.IsSuccessStatusCode)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Экстренное уведомление успешно отправлено в Telegram!");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Ошибка отправки в Telegram: {ex.Message}");
            }
        }
        #endregion

        #region Forensic File Collector & Hasher
        private static List<FileEvidence> CollectEvidenceFiles()
        {
            var files = new List<FileEvidence>();
            var pathsToCheck = new List<string>();

            string? appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (!string.IsNullOrEmpty(appdata))
            {
                pathsToCheck.Add(Path.Combine(appdata, "AnyDesk", "ad.trace"));
                pathsToCheck.Add(Path.Combine(appdata, "AnyDesk", "connection_trace.txt"));
                pathsToCheck.Add(Path.Combine(appdata, "AnyDesk", "user.conf"));
            }

            string? programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (!string.IsNullOrEmpty(programData))
            {
                pathsToCheck.Add(Path.Combine(programData, "AnyDesk", "ad_svc.trace"));
                pathsToCheck.Add(Path.Combine(programData, "AnyDesk", "ad.trace"));
                pathsToCheck.Add(Path.Combine(programData, "AnyDesk", "system.conf"));
            }

            using var sha256 = SHA256.Create();

            foreach (var p in pathsToCheck.Distinct())
            {
                if (File.Exists(p))
                {
                    try
                    {
                        var fi = new FileInfo(p);
                        using var fs = new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        byte[] hash = sha256.ComputeHash(fs);
                        string hashStr = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();

                        files.Add(new FileEvidence
                        {
                            FilePath = p,
                            FileSizeBytes = fi.Length,
                            LastModified = fi.LastWriteTime,
                            Sha256Hash = hashStr
                        });
                    }
                    catch { }
                }
            }
            return files;
        }
        #endregion

        #region Deep Log Parsing
        private static List<LogEntry> ParseLogsDetailed(List<FileEvidence> evidenceFiles)
        {
            var entries = new List<LogEntry>();
            var ipRegex = new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b");
            var idRegex = new Regex(@"(?:Logged in from|User-ID|Incoming session request:|Client-ID:|ad:)\s*(\d{7,10})", RegexOptions.IgnoreCase);
            var dateRegex = new Regex(@"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})");

            foreach (var ev in evidenceFiles)
            {
                if (!ev.FilePath.EndsWith(".trace", StringComparison.OrdinalIgnoreCase) && 
                    !ev.FilePath.EndsWith("connection_trace.txt", StringComparison.OrdinalIgnoreCase))
                    continue;

                try
                {
                    using var fs = new FileStream(ev.FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8);
                    string? line;
                    int lineNum = 0;

                    while ((line = sr.ReadLine()) != null)
                    {
                        lineNum++;
                        string lower = line.ToLowerInvariant();

                        bool isRelevant = lower.Contains("logged in") || lower.Contains("incoming session") || 
                                          lower.Contains("external ip") || lower.Contains("relay") || 
                                          lower.Contains("p2p") || lower.Contains("accept") || lower.Contains("rejected");

                        if (isRelevant)
                        {
                            DateTime? dt = null;
                            var dateMatch = dateRegex.Match(line);
                            if (dateMatch.Success && DateTime.TryParse(dateMatch.Value, out var parsedDt))
                            {
                                dt = parsedDt;
                            }

                            string anydeskId = "";
                            var idMatch = idRegex.Match(line);
                            if (idMatch.Success) anydeskId = idMatch.Groups[1].Value;

                            string ip = "";
                            var ipMatch = ipRegex.Match(line);
                            if (ipMatch.Success && !IsPrivateIp(ipMatch.Value))
                            {
                                ip = ipMatch.Value;
                            }

                            string evtType = "Событие соединения";
                            if (lower.Contains("incoming session")) evtType = "Запрос входящей сессии";
                            else if (lower.Contains("logged in")) evtType = "Успешный вход в систему";
                            else if (lower.Contains("relay")) evtType = "Трафик через Relay-сервер";
                            else if (lower.Contains("p2p")) evtType = "Прямое P2P соединение";

                            entries.Add(new LogEntry
                            {
                                Timestamp = dt,
                                SourceFile = Path.GetFileName(ev.FilePath),
                                LineNumber = lineNum,
                                EventType = evtType,
                                AnyDeskId = anydeskId,
                                IpAddress = ip,
                                RawLine = line.Trim()
                            });
                        }
                    }
                }
                catch { }
            }

            return entries.OrderByDescending(e => e.Timestamp ?? DateTime.MinValue).ToList();
        }
        #endregion

        #region Active Win32 Connections
        private static List<LogEntry> GetActiveAnyDeskConnections()
        {
            var results = new List<LogEntry>();
            var anydeskPids = new HashSet<int>();
            foreach (var p in Process.GetProcessesByName("AnyDesk")) anydeskPids.Add(p.Id);
            if (anydeskPids.Count == 0) return results;

            var rows = GetAllTcpConnections();
            foreach (var row in rows)
            {
                if (anydeskPids.Contains((int)row.owningPid) && row.state == MIB_TCP_STATE.MIB_TCP_STATE_ESTAB)
                {
                    string remoteIp = new IPAddress(row.remoteAddr).ToString();
                    int remotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.remotePort);

                    if (!IsPrivateIp(remoteIp))
                    {
                        results.Add(new LogEntry
                        {
                            Timestamp = DateTime.Now,
                            SourceFile = "Live TCP Socket",
                            LineNumber = 0,
                            EventType = "🔴 Активное TCP соединение",
                            IpAddress = remoteIp,
                            RawLine = $"PID: {row.owningPid} (AnyDesk.exe) -> Remote Port: {remotePort}"
                        });
                    }
                }
            }
            return results;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TCP_TABLE_CLASS TableClass, uint Reserved = 0);
        private enum TCP_TABLE_CLASS { TCP_TABLE_OWNER_PID_ALL = 5 }
        private enum MIB_TCP_STATE { MIB_TCP_STATE_ESTAB = 5 }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public MIB_TCP_STATE state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        private static List<MIB_TCPROW_OWNER_PID> GetAllTcpConnections()
        {
            var rows = new List<MIB_TCPROW_OWNER_PID>();
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL) == 0)
                {
                    int rowCount = Marshal.ReadInt32(tcpTablePtr);
                    IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
                    for (int i = 0; i < rowCount; i++)
                    {
                        rows.Add(Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr));
                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID)));
                    }
                }
            }
            finally { Marshal.FreeHGlobal(tcpTablePtr); }
            return rows;
        }

        private static bool IsPrivateIp(string ipStr)
        {
            if (IPAddress.TryParse(ipStr, out var ip))
            {
                byte[] b = ip.GetAddressBytes();
                if (b.Length != 4) return true;
                if (b[0] == 10 || b[0] == 127 || b[0] == 0) return true;
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
                if (b[0] == 192 && b[1] == 168) return true;
                return false;
            }
            return true;
        }

        private static async Task<GeoIpResponse?> FetchGeoIpAsync(string ip)
        {
            try
            {
                string url = $"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,query";
                var res = await httpClient.GetStringAsync(url);
                return JsonSerializer.Deserialize<GeoIpResponse>(res);
            }
            catch { return null; }
        }
        #endregion

        #region Report & Statement Generation
        private static void GenerateForensicHtmlReport(string path, List<LogEntry> timeline, List<FileEvidence> evidence)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"UTF-8\">");
            sb.AppendLine("<title>Криминалистический отчет AnyDesk</title>");
            // Подключаем Leaflet CSS и JS для интерактивной карты
            sb.AppendLine("<link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.css\" />");
            sb.AppendLine("<script src=\"https://unpkg.com/leaflet@1.9.4/dist/leaflet.js\"></script>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 30px; background: #f4f6f9; color: #212529; }");
            sb.AppendLine(".card { background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); padding: 20px; margin-bottom: 25px; }");
            sb.AppendLine("h1, h2, h3 { color: #1a73e8; margin-top: 0; }");
            sb.AppendLine("#map { height: 380px; width: 100%; border-radius: 6px; }");
            sb.AppendLine("table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }");
            sb.AppendLine("th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e9ecef; }");
            sb.AppendLine("th { background-color: #f8f9fa; font-weight: 600; color: #495057; }");
            sb.AppendLine(".badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }");
            sb.AppendLine(".badge-active { background: #d4edda; color: #155724; }");
            sb.AppendLine(".badge-event { background: #e2e3e5; color: #383d41; }");
            sb.AppendLine(".hash-box { font-family: monospace; font-size: 12px; background: #e9ecef; padding: 4px 6px; border-radius: 3px; word-break: break-all; }");
            sb.AppendLine("</style></head><body>");

            sb.AppendLine("<h1>Криминалистический отчет инцидента AnyDesk</h1>");
            sb.AppendLine($"<p style=\"color: #6c757d;\">Сформирован: <b>{DateTime.Now:yyyy-MM-dd HH:mm:ss}</b> | Хост: <b>{Environment.MachineName}</b> | Пользователь: <b>{Environment.UserName}</b></p>");

            // Карта
            sb.AppendLine("<div class=\"card\"><h2>🗺️ Интерактивная карта геопозиций подключений</h2><div id=\"map\"></div></div>");

            // Таблица доказательств (Целостность данных)
            sb.AppendLine("<div class=\"card\"><h2>🔒 Сохранность цифровых улик (Chain of Custody)</h2>");
            sb.AppendLine("<table><thead><tr><th>Файл логов</th><th>Размер</th><th>Последнее изменение</th><th>SHA-256 Контрольная сумма</th></tr></thead><tbody>");
            foreach (var ev in evidence)
            {
                sb.AppendLine($"<tr><td><b>{Path.GetFileName(ev.FilePath)}</b><br><small style='color:#6c757d;'>{ev.FilePath}</small></td><td>{ev.FileSizeBytes} байт</td><td>{ev.LastModified:yyyy-MM-dd HH:mm:ss}</td><td><span class=\"hash-box\">{ev.Sha256Hash}</span></td></tr>");
            }
            sb.AppendLine("</tbody></table></div>");

            // Криминалистический таймлайн
            sb.AppendLine("<div class=\"card\"><h2>⏱️ Таймлайн событий и сессий</h2>");
            sb.AppendLine("<table><thead><tr><th>Время</th><th>Тип события</th><th>AnyDesk ID</th><th>IP-адрес</th><th>Локация / Провайдер</th><th>Исходный лог</th></tr></thead><tbody>");

            var mapMarkers = new List<string>();
            foreach (var item in timeline)
            {
                string timeStr = item.Timestamp.HasValue ? item.Timestamp.Value.ToString("yyyy-MM-dd HH:mm:ss") : "-";
                string badge = item.EventType.Contains("Активное") ? "badge-active" : "badge-event";
                string geoStr = item.GeoData?.Status == "success" ? $"{item.GeoData.Country}, {item.GeoData.City}<br><small>{item.GeoData.Isp}</small>" : "-";
                
                sb.AppendLine("<tr>");
                sb.AppendLine($"<td>{timeStr}</td>");
                sb.AppendLine($"<td><span class=\"badge {badge}\">{item.EventType}</span></td>");
                sb.AppendLine($"<td><code>{item.AnyDeskId}</code></td>");
                sb.AppendLine($"<td><b>{item.IpAddress}</b></td>");
                sb.AppendLine($"<td>{geoStr}</td>");
                sb.AppendLine($"<td style=\"font-family: monospace; font-size: 11px; word-break: break-all;\">{item.RawLine}</td>");
                sb.AppendLine("</tr>");

                if (item.GeoData?.Status == "success" && item.GeoData.Lat.HasValue && item.GeoData.Lon.HasValue)
                {
                    mapMarkers.Add($"L.marker([{item.GeoData.Lat.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)}, {item.GeoData.Lon.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)}]).addTo(map).bindPopup('<b>IP: {item.IpAddress}</b><br>{item.GeoData.City}, {item.GeoData.Country}<br>Провайдер: {item.GeoData.Isp}');");
                }
            }
            sb.AppendLine("</tbody></table></div>");

            // Инициализация скрипта Leaflet Map
            sb.AppendLine("<script>");
            sb.AppendLine("var map = L.map('map').setView([45, 25], 3);");
            sb.AppendLine("L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18, attribution: '© OpenStreetMap' }).addTo(map);");
            foreach (var m in mapMarkers.Distinct()) sb.AppendLine(m);
            sb.AppendLine("</script>");

            sb.AppendLine("</body></html>");
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        private static void GeneratePoliceStatement(string path, List<LogEntry> timeline, List<FileEvidence> evidence)
        {
            var firstSession = timeline.LastOrDefault(t => !string.IsNullOrEmpty(t.IpAddress));
            var latestSession = timeline.FirstOrDefault(t => !string.IsNullOrEmpty(t.IpAddress));
            var uniqueIds = timeline.Where(t => !string.IsNullOrEmpty(t.AnyDeskId)).Select(t => t.AnyDeskId).Distinct().ToList();
            var uniqueIps = timeline.Where(t => !string.IsNullOrEmpty(t.IpAddress) && t.GeoData?.Status == "success").ToList();

            var sb = new StringBuilder();
            sb.AppendLine("В Орган внутренних дел / Службу безопасности Банка");
            sb.AppendLine($"От гражданина(ки): _____________________________________________");
            sb.AppendLine($"Проживающего(ей) по адресу: ___________________________________");
            sb.AppendLine($"Контактный телефон: ___________________________________________\n");
            sb.AppendLine("                             ЗАЯВЛЕНИЕ");
            sb.AppendLine("    о факте несанкционированного удаленного доступа (компьютерного мошенничества)\n");
            sb.AppendLine($"Настоящим сообщаю, что на моем персональном компьютере (имя устройства: {Environment.MachineName})");
            sb.AppendLine("был зафиксирован факт неправомерного удаленного доступа с использованием программного обеспечения AnyDesk.\n");

            sb.AppendLine("1. СВЕДЕНИЯ О ПОДКЛЮЧЕНИИ:");
            sb.AppendLine($"• Дата и время фиксации: {(firstSession?.Timestamp.HasValue == true ? firstSession.Timestamp.Value.ToString("yyyy-MM-dd HH:mm:ss") : DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"))}");
            sb.AppendLine($"• Идентификаторы AnyDesk злоумышленников (User ID): {(uniqueIds.Count > 0 ? string.Join(", ", uniqueIds) : "В процессе извлечения из дампа")}");
            
            sb.AppendLine("\n2. СЕТЕВЫЕ АДРЕСА И ГЕОЛОКАЦИЯ ЗЛОУМЫШЛЕННИКА:");
            foreach (var item in uniqueIps.Take(5))
            {
                var g = item.GeoData;
                sb.AppendLine($"• IP: {item.IpAddress} | Страна/Город: {g?.Country}, {g?.City} | Провайдер: {g?.Isp} | Организация: {g?.Org ?? g?.As}");
            }

            sb.AppendLine("\n3. ЦИФРОВЫЕ ДОКАЗАТЕЛЬСТВА (ХЭШ-СУММЫ SHA-256):");
            sb.AppendLine("Для исключения сомнений в неизменности журналов логов зафиксированы контрольные суммы файлов:");
            foreach (var ev in evidence)
            {
                sb.AppendLine($"• {Path.GetFileName(ev.FilePath)} (SHA-256: {ev.Sha256Hash})");
            }

            sb.AppendLine("\nПриложения: Полный криминалистический отчет (HTML/JSON), исходные лог-файлы.");
            sb.AppendLine("\nДата: " + DateTime.Now.ToString("dd.MM.yyyy"));
            sb.AppendLine("Подпись: __________________ / __________________ /");

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        private static void GenerateJsonReport(string path, List<LogEntry> timeline, List<FileEvidence> evidence)
        {
            var data = new
            {
                GeneratedAt = DateTime.Now,
                Hostname = Environment.MachineName,
                User = Environment.UserName,
                EvidenceFiles = evidence,
                Timeline = timeline
            };
            string json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json, Encoding.UTF8);
        }
        #endregion
    }
}
