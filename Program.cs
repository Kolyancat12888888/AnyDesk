using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

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

    public class SessionEvent
    {
        public string Timestamp { get; set; } = "";
        public string EventType { get; set; } = "";
        public string RemoteAnyDeskId { get; set; } = "Неизвестен";
        public string RemoteIp { get; set; } = "Через релей AnyDesk";
        public string Location { get; set; } = "-";
        public string IspOrg { get; set; } = "-";
        public string ConnectionType { get; set; } = "Relay / Не определен";
        public string LogSource { get; set; } = "";
        public GeoIpResponse? Geo { get; set; }
    }

    public class MainForm : Form
    {
        private DataGridView grid;
        private Label lblStatus;
        private Label lblSessionCount;
        private Button btnLiveProtect;
        private Button btnStopProtect;
        private Button btnScanRealSessions;
        private Button btnKillAnyDesk;
        private Button btnExportHtml;
        private System.Windows.Forms.Timer liveLogWatcherTimer;
        
        private readonly HttpClient httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        private readonly List<SessionEvent> sessionList = new List<SessionEvent>();
        private readonly HashSet<string> seenSessionKeys = new HashSet<string>();
        private long lastLogPosition = 0;
        private string? activeLogPath = null;

        public MainForm()
        {
            InitializeComponent();
            FindActiveLogFile();
        }

        private void InitializeComponent()
        {
            this.Text = "🛡️ AnyDesk Anti-Scam Inspector (Точный детектор сессий)";
            this.Size = new Size(1100, 650);
            this.MinimumSize = new Size(900, 520);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(246, 248, 251);
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

            // Верхняя панель
            var topPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 85,
                Padding = new Padding(12),
                BackColor = Color.White
            };

            btnLiveProtect = CreateStyledButton("▶ Включить защиту сессий", Color.FromArgb(40, 167, 69), Color.White, 220);
            btnLiveProtect.Click += (s, e) => ToggleLiveProtection(true);

            btnStopProtect = CreateStyledButton("⏸ Пауза", Color.FromArgb(108, 117, 125), Color.White, 100);
            btnStopProtect.Enabled = false;
            btnStopProtect.Click += (s, e) => ToggleLiveProtection(false);

            btnScanRealSessions = CreateStyledButton("🔍 Найти реальные сессии в истории", Color.FromArgb(0, 123, 255), Color.White, 260);
            btnScanRealSessions.Click += async (s, e) => await LoadActualSessionsFromLogsAsync();

            btnKillAnyDesk = CreateStyledButton("🚨 ЭКСТРЕННО СБРОСИТЬ СЕССИЮ", Color.FromArgb(220, 53, 69), Color.White, 250);
            btnKillAnyDesk.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            btnKillAnyDesk.Click += (s, e) => KillAnyDesk();

            topPanel.Controls.Add(btnLiveProtect);
            topPanel.Controls.Add(btnStopProtect);
            topPanel.Controls.Add(btnScanRealSessions);
            topPanel.Controls.Add(btnKillAnyDesk);

            btnLiveProtect.Location = new Point(12, 20);
            btnStopProtect.Location = new Point(240, 20);
            btnScanRealSessions.Location = new Point(350, 20);
            btnKillAnyDesk.Location = new Point(620, 20);

            // Таблица
            grid = new DataGridView
            {
                Dock = DockStyle.Fill,
                BackgroundColor = Color.White,
                BorderStyle = BorderStyle.None,
                RowHeadersVisible = false,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                ReadOnly = true,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
            };
            grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(230, 240, 255);
            grid.DefaultCellStyle.SelectionForeColor = Color.Black;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(240, 243, 246);
            grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            grid.ColumnHeadersHeight = 36;
            grid.EnableHeadersVisualStyles = false;

            grid.Columns.Add("Time", "Время");
            grid.Columns.Add("Event", "Статус сессии");
            grid.Columns.Add("AnyDeskId", "ID оператора (AnyDesk ID)");
            grid.Columns.Add("Ip", "IP-адрес оператора");
            grid.Columns.Add("Type", "Тип связи");
            grid.Columns.Add("Location", "Локация оператора");
            grid.Columns.Add("Isp", "Провайдер / Сеть");

            grid.Columns[0].FillWeight = 110;
            grid.Columns[1].FillWeight = 130;
            grid.Columns[2].FillWeight = 140;
            grid.Columns[3].FillWeight = 120;
            grid.Columns[4].FillWeight = 110;
            grid.Columns[5].FillWeight = 150;
            grid.Columns[6].FillWeight = 160;

            // Нижняя панель
            var bottomPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 55,
                Padding = new Padding(12),
                BackColor = Color.White
            };

            lblStatus = new Label
            {
                Text = "Готов. Нажмите «Найти реальные сессии в истории» или запустите защиту в реальном времени.",
                Dock = DockStyle.Left,
                AutoSize = true,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(80, 90, 105)
            };

            btnExportHtml = CreateStyledButton("📊 Сохранить отчет (HTML)", Color.FromArgb(23, 162, 184), Color.White, 200);
            btnExportHtml.Dock = DockStyle.Right;
            btnExportHtml.Click += (s, e) => ExportHtmlReport();

            bottomPanel.Controls.Add(lblStatus);
            bottomPanel.Controls.Add(btnExportHtml);

            this.Controls.Add(grid);
            this.Controls.Add(bottomPanel);
            this.Controls.Add(topPanel);

            liveLogWatcherTimer = new System.Windows.Forms.Timer { Interval = 1500 };
            liveLogWatcherTimer.Tick += async (s, e) => await CheckLiveLogUpdatesAsync();
        }

        private Button CreateStyledButton(string text, Color bg, Color fg, int width)
        {
            var btn = new Button
            {
                Text = text,
                BackColor = bg,
                ForeColor = fg,
                FlatStyle = FlatStyle.Flat,
                Width = width,
                Height = 42,
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderSize = 0;
            return btn;
        }

        private void FindActiveLogFile()
        {
            string? appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (!string.IsNullOrEmpty(appdata))
            {
                string p = Path.Combine(appdata, "AnyDesk", "ad.trace");
                if (File.Exists(p)) activeLogPath = p;
            }

            if (activeLogPath == null)
            {
                string? programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                if (!string.IsNullOrEmpty(programData))
                {
                    string p = Path.Combine(programData, "AnyDesk", "ad_svc.trace");
                    if (File.Exists(p)) activeLogPath = p;
                }
            }

            if (activeLogPath != null && File.Exists(activeLogPath))
            {
                try { lastLogPosition = new FileInfo(activeLogPath).Length; } catch { }
            }
        }

        private void ToggleLiveProtection(bool enable)
        {
            btnLiveProtect.Enabled = !enable;
            btnStopProtect.Enabled = enable;

            if (enable)
            {
                FindActiveLogFile();
                lblStatus.Text = "🟢 Защита ВКЛЮЧЕНА: ожидание реального подключения оператора...";
                lblStatus.ForeColor = Color.FromArgb(40, 167, 69);
                liveLogWatcherTimer.Start();
            }
            else
            {
                lblStatus.Text = "⏸ Защита на паузе.";
                lblStatus.ForeColor = Color.FromArgb(108, 117, 125);
                liveLogWatcherTimer.Stop();
            }
        }

        private async Task CheckLiveLogUpdatesAsync()
        {
            if (string.IsNullOrEmpty(activeLogPath) || !File.Exists(activeLogPath))
            {
                FindActiveLogFile();
                return;
            }

            try
            {
                var fi = new FileInfo(activeLogPath);
                if (fi.Length > lastLogPosition)
                {
                    using (var fs = new FileStream(activeLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        fs.Seek(lastLogPosition, SeekOrigin.Begin);
                        using (var sr = new StreamReader(fs, Encoding.UTF8))
                        {
                            string? line;
                            while ((line = sr.ReadLine()) != null)
                            {
                                var ev = TryParseSessionLine(line, Path.GetFileName(activeLogPath));
                                if (ev != null)
                                {
                                    string key = $"{ev.Timestamp}_{ev.RemoteAnyDeskId}_{ev.EventType}";
                                    if (!seenSessionKeys.Contains(key))
                                    {
                                        seenSessionKeys.Add(key);
                                        System.Media.SystemSounds.Hand.Play();

                                        if (ev.RemoteIp != "Через релей AnyDesk" && !IsPrivateIp(ev.RemoteIp))
                                        {
                                            ev.Geo = await FetchGeoIpAsync(ev.RemoteIp);
                                            if (ev.Geo?.Status == "success")
                                            {
                                                ev.Location = $"{ev.Geo.Country}, {ev.Geo.City}";
                                                ev.IspOrg = $"{ev.Geo.Isp} ({ev.Geo.Org ?? ev.Geo.As})";
                                            }
                                        }

                                        sessionList.Insert(0, ev);
                                        grid.Rows.Insert(0, ev.Timestamp, ev.EventType, ev.RemoteAnyDeskId, ev.RemoteIp, ev.ConnectionType, ev.Location, ev.IspOrg);
                                        grid.Rows[0].DefaultCellStyle.BackColor = Color.FromArgb(255, 235, 238);
                                        grid.Rows[0].DefaultCellStyle.ForeColor = Color.FromArgb(198, 40, 40);

                                        lblStatus.Text = $"🚨 ВНИМАНИЕ: Зафиксировано событие AnyDesk ID: {ev.RemoteAnyDeskId} ({ev.EventType})!";
                                        lblStatus.ForeColor = Color.Red;
                                    }
                                }
                            }
                            lastLogPosition = fs.Position;
                        }
                    }
                }
            }
            catch { }
        }

        private async Task LoadActualSessionsFromLogsAsync()
        {
            lblStatus.Text = "Поиск реальных сессий в логах AnyDesk...";
            sessionList.Clear();
            seenSessionKeys.Clear();
            grid.Rows.Clear();

            var logs = new List<string>();
            string? appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (!string.IsNullOrEmpty(appdata))
            {
                logs.Add(Path.Combine(appdata, "AnyDesk", "ad.trace"));
                logs.Add(Path.Combine(appdata, "AnyDesk", "connection_trace.txt"));
            }
            string? progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (!string.IsNullOrEmpty(progData))
            {
                logs.Add(Path.Combine(progData, "AnyDesk", "ad_svc.trace"));
                logs.Add(Path.Combine(progData, "AnyDesk", "ad.trace"));
            }

            foreach (var logFile in logs)
            {
                if (!File.Exists(logFile)) continue;
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8);
                    string? line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        var ev = TryParseSessionLine(line, Path.GetFileName(logFile));
                        if (ev != null)
                        {
                            string key = $"{ev.Timestamp}_{ev.RemoteAnyDeskId}_{ev.EventType}";
                            if (!seenSessionKeys.Contains(key))
                            {
                                seenSessionKeys.Add(key);
                                sessionList.Add(ev);
                            }
                        }
                    }
                }
                catch { }
            }

            if (sessionList.Count == 0)
            {
                MessageBox.Show("В логах не найдено реальных входящих сессий.\n(Служебные системные соединения отфильтрованы).", "Информация", MessageBoxButtons.OK, MessageBoxIcon.Information);
                lblStatus.Text = "Реальных сессий не зафиксировано.";
                return;
            }

            lblStatus.Text = $"Найдено {sessionList.Count} реальных сессий. Определение GeoIP...";

            foreach (var ev in sessionList)
            {
                if (ev.RemoteIp != "Через релей AnyDesk" && !IsPrivateIp(ev.RemoteIp))
                {
                    ev.Geo = await FetchGeoIpAsync(ev.RemoteIp);
                    if (ev.Geo?.Status == "success")
                    {
                        ev.Location = $"{ev.Geo.Country}, {ev.Geo.City}";
                        ev.IspOrg = $"{ev.Geo.Isp} ({ev.Geo.Org ?? ev.Geo.As})";
                    }
                    await Task.Delay(200);
                }
                grid.Rows.Add(ev.Timestamp, ev.EventType, ev.RemoteAnyDeskId, ev.RemoteIp, ev.ConnectionType, ev.Location, ev.IspOrg);
            }

            lblStatus.Text = $"Загружено {sessionList.Count} подтвержденных сеансов AnyDesk.";
        }

        private SessionEvent? TryParseSessionLine(string line, string fileName)
        {
            string lower = line.ToLowerInvariant();

            // Исключаем фоновые служебные строки (пинг серверов, резолв DNS, токены)
            if (lower.Contains("checking for updates") || lower.Contains("heartbeat") || 
                lower.Contains("license check") || lower.Contains("stun response"))
                return null;

            bool isIncomingRequest = lower.Contains("incoming session request") || lower.Contains("request from");
            bool isLoggedIn = lower.Contains("logged in from") || lower.Contains("user-id:");
            bool isAccepted = lower.Contains("session accepted") || lower.Contains("session started");
            bool isRejected = lower.Contains("session closed") || lower.Contains("session terminated") || lower.Contains("rejected");

            if (!isIncomingRequest && !isLoggedIn && !isAccepted && !isRejected)
                return null;

            // Извлечение AnyDesk ID (7-10 цифр)
            var idMatch = Regex.Match(line, @"(?:Logged in from|User-ID:|request:\s*|from\s+|ad:)(\d{7,10})", RegexOptions.IgnoreCase);
            if (!idMatch.Success)
            {
                // Если нет ID оператора в строке, проверяем наличие ключевого слова сессии
                if (!lower.Contains("session")) return null;
            }

            string anyId = idMatch.Success ? idMatch.Groups[1].Value : "Не указан";

            // Извлечение внешнего IP, если есть в строке
            var ipMatch = Regex.Match(line, @"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b");
            string ip = "Через релей AnyDesk";
            string connType = "Relay (Сервер AnyDesk)";

            if (ipMatch.Success && !IsPrivateIp(ipMatch.Value))
            {
                ip = ipMatch.Value;
                connType = lower.Contains("p2p") || lower.Contains("direct") ? "Прямое P2P" : "Релей / Внешний IP";
            }

            string eventType = "Сессия";
            if (isIncomingRequest) eventType = "🔔 Запрос на подключение";
            else if (isLoggedIn) eventType = "🔑 Успешный вход в систему";
            else if (isAccepted) eventType = "🟢 Сессия начата";
            else if (isRejected) eventType = "🔴 Сессия завершена / Отклонена";

            string timeStr = line.Length >= 19 ? line.Substring(0, 19) : DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            return new SessionEvent
            {
                Timestamp = timeStr,
                EventType = eventType,
                RemoteAnyDeskId = anyId,
                RemoteIp = ip,
                ConnectionType = connType,
                LogSource = fileName
            };
        }

        private void KillAnyDesk()
        {
            try
            {
                int count = 0;
                foreach (var p in Process.GetProcessesByName("AnyDesk"))
                {
                    p.Kill();
                    count++;
                }
                MessageBox.Show($"Процессы AnyDesk ({count} шт.) экстренно закрыты!", "Сброс сессии", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                lblStatus.Text = "🛑 Процессы AnyDesk сброшены!";
                lblStatus.ForeColor = Color.Red;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ExportHtmlReport()
        {
            if (sessionList.Count == 0)
            {
                MessageBox.Show("Нет данных для отчета. Сначала найдите сессии.", "Внимание", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var sfd = new SaveFileDialog
            {
                Filter = "HTML Files (*.html)|*.html",
                FileName = $"AnyDesk_Verified_Report_{DateTime.Now:yyyyMMdd_HHmmss}.html"
            };

            if (sfd.ShowDialog() == DialogResult.OK)
            {
                var sb = new StringBuilder();
                sb.AppendLine("<!DOCTYPE html><html lang='ru'><head><meta charset='UTF-8'><title>Отчет по сессиям AnyDesk</title>");
                sb.AppendLine("<style>body{font-family:sans-serif;margin:30px;background:#f8f9fa} table{width:100%;border-collapse:collapse;background:#fff} th,td{padding:10px;border:1px solid #ddd;text-align:left} th{background:#e9ecef}</style></head><body>");
                sb.AppendLine($"<h2>Подтвержденные сессии AnyDesk ({DateTime.Now})</h2>");
                sb.AppendLine("<table><tr><th>Время</th><th>Статус</th><th>AnyDesk ID оператора</th><th>IP-адрес</th><th>Тип связи</th><th>Локация</th><th>Провайдер</th></tr>");
                foreach (var ev in sessionList)
                {
                    sb.AppendLine($"<tr><td>{ev.Timestamp}</td><td>{ev.EventType}</td><td><b>{ev.RemoteAnyDeskId}</b></td><td>{ev.RemoteIp}</td><td>{ev.ConnectionType}</td><td>{ev.Location}</td><td>{ev.IspOrg}</td></tr>");
                }
                sb.AppendLine("</table></body></html>");
                File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8);
                Process.Start(new ProcessStartInfo(sfd.FileName) { UseShellExecute = true });
            }
        }

        private async Task<GeoIpResponse?> FetchGeoIpAsync(string ip)
        {
            try
            {
                string url = $"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,query";
                var res = await httpClient.GetStringAsync(url);
                return JsonSerializer.Deserialize<GeoIpResponse>(res);
            }
            catch { return null; }
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

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
