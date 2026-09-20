using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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

    public class ConnectionItem
    {
        public string Time { get; set; } = "";
        public string Source { get; set; } = "";
        public string Ip { get; set; } = "";
        public string Location { get; set; } = "";
        public string Isp { get; set; } = "";
        public string Org { get; set; } = "";
        public string Details { get; set; } = "";
        public GeoIpResponse? Geo { get; set; }
    }

    public class MainForm : Form
    {
        private DataGridView grid;
        private Label lblStatus;
        private Button btnStartMonitor;
        private Button btnStopMonitor;
        private Button btnScanHistory;
        private Button btnKillAnyDesk;
        private Button btnExportHtml;
        private Button btnExportPolice;
        private System.Windows.Forms.Timer monitorTimer;
        private readonly HttpClient httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        private readonly HashSet<string> seenIps = new HashSet<string>();
        private readonly List<ConnectionItem> allItems = new List<ConnectionItem>();
        private bool isMonitoring = false;

        public MainForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            this.Text = "🛡️ AnyDesk Anti-Scam & Forensic Inspector";
            this.Size = new Size(1020, 640);
            this.MinimumSize = new Size(850, 500);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(245, 247, 250);
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

            // Верхняя панель кнопок
            var topPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 80,
                Padding = new Padding(12),
                BackColor = Color.White
            };

            btnStartMonitor = CreateStyledButton("▶ Включить защиту (Live)", Color.FromArgb(40, 167, 69), Color.White, 200);
            btnStartMonitor.Click += (s, e) => ToggleMonitoring(true);

            btnStopMonitor = CreateStyledButton("⏸ Пауза", Color.FromArgb(108, 117, 125), Color.White, 100);
            btnStopMonitor.Enabled = false;
            btnStopMonitor.Click += (s, e) => ToggleMonitoring(false);

            btnScanHistory = CreateStyledButton("📜 История подключений (Логи)", Color.FromArgb(0, 123, 255), Color.White, 220);
            btnScanHistory.Click += async (s, e) => await ScanLogsAsync();

            btnKillAnyDesk = CreateStyledButton("🚨 ЭКСТРЕННО УБИТЬ ANYDESK", Color.FromArgb(220, 53, 69), Color.White, 240);
            btnKillAnyDesk.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            btnKillAnyDesk.Click += (s, e) => KillAnyDesk();

            topPanel.Controls.Add(btnStartMonitor);
            topPanel.Controls.Add(btnStopMonitor);
            topPanel.Controls.Add(btnScanHistory);
            topPanel.Controls.Add(btnKillAnyDesk);

            btnStartMonitor.Location = new Point(12, 18);
            btnStopMonitor.Location = new Point(220, 18);
            btnScanHistory.Location = new Point(330, 18);
            btnKillAnyDesk.Location = new Point(560, 18);

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
            grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(232, 240, 254);
            grid.DefaultCellStyle.SelectionForeColor = Color.Black;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(240, 243, 246);
            grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            grid.ColumnHeadersHeight = 35;
            grid.EnableHeadersVisualStyles = false;

            grid.Columns.Add("Time", "Время");
            grid.Columns.Add("Source", "Тип");
            grid.Columns.Add("Ip", "IP-адрес");
            grid.Columns.Add("Location", "Локация (Страна / Город)");
            grid.Columns.Add("Isp", "Провайдер");
            grid.Columns.Add("Org", "Организация / AS");
            grid.Columns.Add("Details", "Детали / User ID");

            grid.Columns[0].FillWeight = 110;
            grid.Columns[1].FillWeight = 90;
            grid.Columns[2].FillWeight = 110;
            grid.Columns[3].FillWeight = 160;
            grid.Columns[4].FillWeight = 140;
            grid.Columns[5].FillWeight = 140;
            grid.Columns[6].FillWeight = 200;

            // Нижняя панель
            var bottomPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 55,
                Padding = new Padding(10),
                BackColor = Color.White
            };

            lblStatus = new Label
            {
                Text = "Готов. Нажмите «Включить защиту» для мониторинга в реальном времени.",
                Dock = DockStyle.Left,
                AutoSize = true,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(70, 80, 95)
            };

            btnExportHtml = CreateStyledButton("📊 Отчет HTML", Color.FromArgb(23, 162, 184), Color.White, 140);
            btnExportHtml.Click += (s, e) => ExportHtmlReport();

            btnExportPolice = CreateStyledButton("📄 Бланк в полицию", Color.FromArgb(108, 117, 125), Color.White, 160);
            btnExportPolice.Click += (s, e) => ExportPoliceStatement();

            btnExportPolice.Dock = DockStyle.Right;
            btnExportHtml.Dock = DockStyle.Right;

            bottomPanel.Controls.Add(lblStatus);
            bottomPanel.Controls.Add(btnExportPolice);
            bottomPanel.Controls.Add(btnExportHtml);

            this.Controls.Add(grid);
            this.Controls.Add(bottomPanel);
            this.Controls.Add(topPanel);

            // Таймер фонового мониторинга
            monitorTimer = new System.Windows.Forms.Timer();
            monitorTimer.Interval = 2000; // каждые 2 сек
            monitorTimer.Tick += async (s, e) => await CheckActiveConnectionsAsync();
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

        private void ToggleMonitoring(bool enable)
        {
            isMonitoring = enable;
            btnStartMonitor.Enabled = !enable;
            btnStopMonitor.Enabled = enable;

            if (enable)
            {
                lblStatus.Text = "🟢 Защита АКТИВНА: сканирование сетевых сокетов AnyDesk каждые 2 сек...";
                lblStatus.ForeColor = Color.FromArgb(40, 167, 69);
                monitorTimer.Start();
            }
            else
            {
                lblStatus.Text = "⏸ Мониторинг на паузе.";
                lblStatus.ForeColor = Color.FromArgb(108, 117, 125);
                monitorTimer.Stop();
            }
        }

        private async Task CheckActiveConnectionsAsync()
        {
            var activeIps = GetActiveAnyDeskConnections();
            if (activeIps.Count == 0) return;

            foreach (var (ip, port, pid) in activeIps)
            {
                if (!seenIps.Contains(ip))
                {
                    seenIps.Add(ip);
                    System.Media.SystemSounds.Exclamation.Play();

                    lblStatus.Text = $"🚨 ОБНАРУЖЕНО ПОДКЛЮЧЕНИЕ: {ip}:{port}!";
                    lblStatus.ForeColor = Color.Red;

                    var geo = await FetchGeoIpAsync(ip);
                    string loc = geo?.Status == "success" ? $"{geo.Country}, {geo.City}" : "Не определено";
                    string isp = geo?.Isp ?? "-";
                    string org = geo?.Org ?? geo?.As ?? "-";

                    var item = new ConnectionItem
                    {
                        Time = DateTime.Now.ToString("HH:mm:ss"),
                        Source = "🔴 LIVE (Сессия)",
                        Ip = ip,
                        Location = loc,
                        Isp = isp,
                        Org = org,
                        Details = $"Remote Port: {port} (PID: {pid})",
                        Geo = geo
                    };

                    allItems.Insert(0, item);
                    grid.Rows.Insert(0, item.Time, item.Source, item.Ip, item.Location, item.Isp, item.Org, item.Details);
                    grid.Rows[0].DefaultCellStyle.BackColor = Color.FromArgb(255, 235, 238);
                    grid.Rows[0].DefaultCellStyle.ForeColor = Color.FromArgb(198, 40, 40);
                }
            }
        }

        private async Task ScanLogsAsync()
        {
            lblStatus.Text = "Чтение лог-файлов AnyDesk...";
            var logItems = ParseAnyDeskLogs();
            if (logItems.Count == 0)
            {
                MessageBox.Show("Логи AnyDesk не найдены или в них нет внешних подключений.", "Информация", MessageBoxButtons.OK, MessageBoxIcon.Information);
                lblStatus.Text = "Логи пусты.";
                return;
            }

            lblStatus.Text = $"Найдено {logItems.Count} записей. Запрос GeoIP...";
            foreach (var item in logItems)
            {
                if (!seenIps.Contains(item.Ip))
                {
                    seenIps.Add(item.Ip);
                    item.Geo = await FetchGeoIpAsync(item.Ip);
                    if (item.Geo?.Status == "success")
                    {
                        item.Location = $"{item.Geo.Country}, {item.Geo.City}";
                        item.Isp = item.Geo.Isp ?? "-";
                        item.Org = item.Geo.Org ?? item.Geo.As ?? "-";
                    }
                    allItems.Add(item);
                    grid.Rows.Add(item.Time, item.Source, item.Ip, item.Location, item.Isp, item.Org, item.Details);
                    await Task.Delay(250);
                }
            }
            lblStatus.Text = $"История логов загружена ({grid.Rows.Count} строк).";
        }

        private void KillAnyDesk()
        {
            try
            {
                int killed = 0;
                foreach (var p in Process.GetProcessesByName("AnyDesk"))
                {
                    p.Kill();
                    killed++;
                }
                MessageBox.Show($"Процессы AnyDesk успешно завершены ({killed} шт.)!", "Экстренная остановка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                lblStatus.Text = "🛑 Все процессы AnyDesk принудительно завершены!";
                lblStatus.ForeColor = Color.Red;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка завершения: {ex.Message}", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ExportHtmlReport()
        {
            if (allItems.Count == 0)
            {
                MessageBox.Show("Нет данных для отчета. Сначала запустите мониторинг или историю.", "Внимание", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var sfd = new SaveFileDialog
            {
                Filter = "HTML Files (*.html)|*.html",
                FileName = $"AnyDesk_Report_{DateTime.Now:yyyyMMdd_HHmmss}.html"
            };

            if (sfd.ShowDialog() == DialogResult.OK)
            {
                var sb = new StringBuilder();
                sb.AppendLine("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Отчет AnyDesk</title>");
                sb.AppendLine("<style>body{font-family:sans-serif;margin:30px;background:#f8f9fa} table{width:100%;border-collapse:collapse;background:#fff} th,td{padding:10px;border:1px solid #ddd;text-align:left} th{background:#e9ecef}</style></head><body>");
                sb.AppendLine($"<h2>Отчет по подключениям AnyDesk ({DateTime.Now})</h2><table>");
                sb.AppendLine("<tr><th>Время</th><th>Тип</th><th>IP</th><th>Локация</th><th>Провайдер</th><th>Организация</th><th>Детали</th></tr>");
                foreach (var it in allItems)
                {
                    sb.AppendLine($"<tr><td>{it.Time}</td><td>{it.Source}</td><td><b>{it.Ip}</b></td><td>{it.Location}</td><td>{it.Isp}</td><td>{it.Org}</td><td>{it.Details}</td></tr>");
                }
                sb.AppendLine("</table></body></html>");
                File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8);
                Process.Start(new ProcessStartInfo(sfd.FileName) { UseShellExecute = true });
            }
        }

        private void ExportPoliceStatement()
        {
            if (allItems.Count == 0)
            {
                MessageBox.Show("Нет данных для формирования заявления.", "Внимание", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var sfd = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt",
                FileName = $"Police_Statement_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };

            if (sfd.ShowDialog() == DialogResult.OK)
            {
                var sb = new StringBuilder();
                sb.AppendLine("В Орган внутренних дел / Службу безопасности Банка\n");
                sb.AppendLine("                           ЗАЯВЛЕНИЕ");
                sb.AppendLine(" о несанкционированном удаленном доступе через AnyDesk\n");
                sb.AppendLine($"Компьютер: {Environment.MachineName} (Пользователь: {Environment.UserName})");
                sb.AppendLine($"Дата формирования: {DateTime.Now:dd.MM.yyyy HH:mm:ss}\n");
                sb.AppendLine("ФИКСИРОВАННЫЕ ВНЕШНИЕ ПОДКЛЮЧЕНИЯ:");
                foreach (var it in allItems)
                {
                    sb.AppendLine($"• [{it.Time}] IP: {it.Ip} | Локация: {it.Location} | Провайдер: {it.Isp} | {it.Details}");
                }
                File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8);
                Process.Start(new ProcessStartInfo(sfd.FileName) { UseShellExecute = true });
            }
        }

        #region Helpers & Network
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

        private static List<ConnectionItem> ParseAnyDeskLogs()
        {
            var list = new List<ConnectionItem>();
            string? appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var paths = new List<string>();
            if (!string.IsNullOrEmpty(appdata))
            {
                paths.Add(Path.Combine(appdata, "AnyDesk", "ad.trace"));
                paths.Add(Path.Combine(appdata, "AnyDesk", "connection_trace.txt"));
            }

            var ipRegex = new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b");
            var idRegex = new Regex(@"(?:Logged in from|User-ID|Incoming session request:|Client-ID:|ad:)\s*(\d{7,10})", RegexOptions.IgnoreCase);

            foreach (var p in paths)
            {
                if (!File.Exists(p)) continue;
                try
                {
                    using var fs = new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8);
                    string? line;
                    while ((line = sr.ReadLine()) != null)
                    {
                        string lower = line.ToLowerInvariant();
                        if (lower.Contains("logged in") || lower.Contains("incoming session") || lower.Contains("external ip") || lower.Contains("p2p"))
                        {
                            var m = ipRegex.Match(line);
                            if (m.Success && !IsPrivateIp(m.Value))
                            {
                                string anyId = "";
                                var idM = idRegex.Match(line);
                                if (idM.Success) anyId = $"ID: {idM.Groups[1].Value}";

                                list.Add(new ConnectionItem
                                {
                                    Time = line.Length >= 19 ? line.Substring(0, 19) : "",
                                    Source = "📜 Лог",
                                    Ip = m.Value,
                                    Details = $"{anyId} ({Path.GetFileName(p)})"
                                });
                            }
                        }
                    }
                }
                catch { }
            }
            return list;
        }

        private static List<(string Ip, int Port, uint Pid)> GetActiveAnyDeskConnections()
        {
            var results = new List<(string, int, uint)>();
            var pids = new HashSet<int>();
            foreach (var p in Process.GetProcessesByName("AnyDesk")) pids.Add(p.Id);
            if (pids.Count == 0) return results;

            var rows = GetAllTcpConnections();
            foreach (var row in rows)
            {
                if (pids.Contains((int)row.owningPid) && row.state == 5) // Established
                {
                    string remoteIp = new IPAddress(row.remoteAddr).ToString();
                    int remotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.remotePort);
                    if (!IsPrivateIp(remoteIp))
                    {
                        results.Add((remoteIp, remotePort, row.owningPid));
                    }
                }
            }
            return results;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int TableClass, uint Reserved = 0);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
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
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2, 5, 0);
            IntPtr ptr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                if (GetExtendedTcpTable(ptr, ref bufferSize, true, 2, 5, 0) == 0)
                {
                    int count = Marshal.ReadInt32(ptr);
                    IntPtr rowPtr = (IntPtr)((long)ptr + 4);
                    for (int i = 0; i < count; i++)
                    {
                        rows.Add(Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr));
                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID)));
                    }
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }
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
        #endregion

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
