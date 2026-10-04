#pragma warning disable SYSLIB0057
using DefaultPolicy = MyFirewall.Desktop.Services.DefaultPolicy;
using Spectre.Console;
using Spectre.Console.Rendering;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

// ─────────────────────────────────────────────────────────────────────────────
//  TUI (Path A rework)
//
//  A small state machine rendered as ONE atomic Spectre.Console Live frame:
//
//    Feed   — tabbed live views (1-7 + System page) with a row cursor
//    Filter — '/' typing mode, client-side filter of the cached connection list
//    Detail — threat-intelligence overlay for the selected connection
//    Confirm— destructive-action confirmations (kill, restore FW)
//    Input  — add IP / add ignored-name prompts
//    Help   — keybinding cheat sheet
//
//  Nothing calls Console.Clear() after startup: overlays swap inside the same
//  Live region and Esc returns to the (still refreshing) feed instantly.
// ─────────────────────────────────────────────────────────────────────────────
static partial class Program
{
    #region TUI State

    enum TuiMode { Feed, Filter, Detail, Confirm, Input, Help }
    enum TuiPage { All, Outbound, Inbound, Blocked, Ignored, Alerts, Domains, System }

    static TuiMode  _mode            = TuiMode.Feed;
    static TuiPage  _page            = TuiPage.All;
    static TuiPage  _pageBeforeSystem = TuiPage.All;
    static int      _cursor          = 0;
    static string   _filterText      = "";
    static string   _toast           = "";
    static DateTime _toastUntil      = DateTime.MinValue;

    static string          _overlayTitle  = "";
    static string          _overlayBody   = "";
    static Action?         _overlayAction = null;   // non-null → Confirm overlay (Enter runs it)
    static string          _inputPrompt   = "";
    static string          _inputValue    = "";
    static Action<string>? _inputAction   = null;

    static readonly string[] TabLabels = { "All", "Outbound", "Inbound", "Blocked", "Ignored", "Alerts", "Domains" };

    // Windows ephemeral port range start — connections with a local port at or
    // above this are client-side (outbound) by convention.
    const int EphemeralPortFloor = 49152;

    static string ConnKey(TcpConnectionInfo c) => $"{c.PID}-{c.RemoteIP}:{c.RemotePort}-{c.LocalPort}";

    /// <summary>Strips leftover Spectre markup tags (older alert producers embed them) then escapes for safe display.</summary>
    static string MarkupSafe(string text) =>
        Markup.Escape(Regex.Replace(text, @"\[/?\w[\w \-]*\]", ""));

    static void ShowToast(string message)
    {
        _toast = message;
        _toastUntil = DateTime.Now.AddSeconds(3);
    }

    #endregion

    #region Frame Builder

    static IRenderable BuildFrame(List<TcpConnectionInfo> connections)
    {
        int windowH, windowW;
        try { windowH = Console.WindowHeight; windowW = Console.WindowWidth; }
        catch { windowH = 30; windowW = 120; }
        windowH = Math.Max(windowH, 12);
        windowW = Math.Max(windowW, 60);

        var elements = new List<IRenderable>
        {
            BuildHeader(),
            BuildTabBar()
        };

        if (_mode == TuiMode.Help)
        {
            elements.Add(BuildHelpPanel(windowH, windowW));
        }
        else if (_mode == TuiMode.Detail)
        {
            elements.Add(new Panel(new Markup(_overlayBody))
                .Header($"[bold cyan]{_overlayTitle}[/]").Border(BoxBorder.Rounded).Expand());
        }
        else if (_mode == TuiMode.Confirm)
        {
            elements.Add(new Panel(new Markup(_overlayBody))
                .Header($"[bold red on black] {_overlayTitle} [/]").Border(BoxBorder.Heavy).Expand());
        }
        else if (_mode == TuiMode.Input)
        {
            var body = new Markup($"\n  [white]{Markup.Escape(_inputValue)}[/][invert] [/]\n");
            elements.Add(new Panel(body).Header($"[bold cyan]{Markup.Escape(_inputPrompt)}[/]").Border(BoxBorder.Rounded).Expand());
        }
        else
        {
            elements.Add(BuildBody(windowH));
        }

        elements.Add(BuildStatusBar());
        elements.Add(BuildFooter());
        return new Rows(elements);
    }

    static IRenderable BuildHeader()
    {
        string etw      = _etwTracker?.IsRunning == true ? "[green]●[/]" : "[red]●[/]";
        string strategy = _etwTracker?.MonitoringStrategy.ToString() ?? "N/A";
        string ver      = typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "?";
        return new Markup(
            $" [bold cyan]TCP-MONITOR[/] [grey]v{ver}[/]   " +
            $"ETW {etw} [grey]{Markup.Escape(strategy)}[/]   " +
            $"[grey]rules:[/][red]{_blockedIPs.Count}[/] [grey]ignored:[/][yellow]{_ignoredProcesses.Count}[/]   " +
            $"[grey]{DateTime.Now:HH:mm:ss}[/]");
    }

    static IRenderable BuildTabBar()
    {
        var sb = new StringBuilder(" ");
        for (int i = 0; i < TabLabels.Length; i++)
        {
            string label = Markup.Escape($"[{i + 1}]{TabLabels[i]}");
            sb.Append(_page == (TuiPage)i ? $"[bold cyan]{label}[/]  " : $"[grey]{label}[/]  ");
        }
        string sysLabel = Markup.Escape("[S]System");
        sb.Append(_page == TuiPage.System ? $"[bold cyan]{sysLabel}[/]" : $"[grey]{sysLabel}[/]");

        if (!string.IsNullOrEmpty(_filterText))
            sb.Append($"   [cyan]/{Markup.Escape(_filterText)}[/]");
        return new Markup(sb.ToString());
    }

    static IRenderable BuildBody(int windowH)
    {
        int visible = Math.Max(3, windowH - 10);
        return _page switch
        {
            TuiPage.All or TuiPage.Outbound or TuiPage.Inbound => BuildConnectionTable(visible),
            TuiPage.Blocked => BuildBlockedPage(visible),
            TuiPage.Ignored => BuildIgnoredPage(visible),
            TuiPage.Alerts  => BuildAlertsPage(visible),
            TuiPage.Domains => BuildDomainsPage(visible),
            TuiPage.System  => BuildSystemPage(visible),
            _ => new Markup("")
        };
    }

    /// <summary>Wraps a cell's markup in the selection background when the row is selected.</summary>
    static string Cell(string markup, bool selected) => selected ? $"[black on cyan]{markup}[/]" : markup;

    static IRenderable BuildConnectionTable(int visible)
    {
        var rows = VisibleConnections();
        if (_cursor >= rows.Count) _cursor = Math.Max(0, rows.Count - 1);

        int start = 0;
        if (rows.Count > visible)
            start = Math.Clamp(_cursor - visible / 2, 0, rows.Count - visible);

        var table = new Table().Border(TableBorder.Rounded).Expand();
        table.Title = new TableTitle(
            _page switch
            {
                TuiPage.Outbound => "[bold]OUTBOUND (local ephemeral port)[/]",
                TuiPage.Inbound  => "[bold]INBOUND (local well-known port)[/]",
                _                => "[bold cyan]LIVE FEED[/]"
            });

        table.AddColumn(new TableColumn("#").NoWrap());
        table.AddColumn(new TableColumn("Process").NoWrap());
        table.AddColumn(new TableColumn("PID").NoWrap());
        table.AddColumn(new TableColumn("Remote Address").NoWrap());
        table.AddColumn(new TableColumn("Geo / Org").NoWrap());
        table.AddColumn(new TableColumn("Domain").NoWrap());
        table.AddColumn(new TableColumn("Time").NoWrap());
        table.AddColumn(new TableColumn("Sent").RightAligned().NoWrap());
        table.AddColumn(new TableColumn("Recv").RightAligned().NoWrap());

        if (rows.Count == 0)
        {
            table.AddRow("[grey]--[/]",
                string.IsNullOrEmpty(_filterText) ? "[grey](no active connections)[/]" : "[grey](no matches for filter)[/]",
                "", "", "", "", "", "", "");
            return table;
        }

        int shown = 0;
        for (int i = start; i < rows.Count && shown < visible; i++, shown++)
        {
            var c = rows[i];
            bool selected = i == _cursor;
            bool isNew    = _connectionStartTimes.TryGetValue(ConnKey(c), out var t0)
                            && (DateTime.Now - t0).TotalSeconds < 3;
            bool isBlocked = _blockedIPs.ContainsKey(c.RemoteIP) || _blockedProcessNames.Contains(c.ProcessName);

            string num   = selected ? "▶" : (i + 1).ToString();
            string proc  = c.IsGhosted
                ? $"[grey]{Markup.Escape(c.ProcessName)} (closed)[/]"
                : (isNew ? $"[green bold]✦ {Markup.Escape(c.ProcessName)}[/]"
                         : $"[bold white]{Markup.Escape(c.ProcessName)}[/]");
            string ip    = isBlocked ? $"[red]{Markup.Escape(c.RemoteIP)}[/]" : Markup.Escape(c.RemoteIP);

            table.AddRow(
                Cell(MarkupSafe(num), selected),
                Cell(proc, selected),
                Cell($"[grey]{c.PID}[/]", selected),
                Cell(ip, selected),
                Cell($"[magenta]{MarkupSafe(c.Geo)}[/]", selected),
                Cell($"[blue]{MarkupSafe(c.Domain)}[/]", selected),
                Cell(MarkupSafe(c.Duration), selected),
                Cell($"[green]{MarkupSafe(c.TotalSent)}[/]", selected),
                Cell($"[yellow]{MarkupSafe(c.TotalReceived)}[/]", selected));
        }

        return table;
    }

    static IRenderable BuildBlockedPage(int visible)
    {
        var entries = _blockedIPs.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase).ToList();
        if (_cursor >= entries.Count) _cursor = Math.Max(0, entries.Count - 1);

        int start = 0;
        if (entries.Count > visible)
            start = Math.Clamp(_cursor - visible / 2, 0, entries.Count - visible);

        var table = new Table().Border(TableBorder.Rounded).Expand();
        table.Title = new TableTitle("[bold red]BLOCKED RULES[/] [grey](X/Space remove · A add IP · default opt-outs are remembered)[/]");
        table.AddColumn(new TableColumn("").NoWrap());
        table.AddColumn(new TableColumn("Target").NoWrap());
        table.AddColumn(new TableColumn("Type").NoWrap());
        table.AddColumn(new TableColumn("Process").NoWrap());
        table.AddColumn(new TableColumn("Since").NoWrap());

        if (entries.Count == 0) { table.AddRow("", "[grey](none)[/]", "", "", ""); return table; }

        int shown = 0;
        for (int i = start; i < entries.Count && shown < visible; i++, shown++)
        {
            var kvp = entries[i];
            bool selected = i == _cursor;
            bool isIp = IsValidIP(kvp.Key);
            table.AddRow(
                Cell(selected ? "▶" : "", selected),
                Cell(isIp ? $"[red]{Markup.Escape(kvp.Key)}[/]" : $"[yellow]{Markup.Escape(kvp.Key)}[/]", selected),
                Cell(isIp ? "IP" : "PROC", selected),
                Cell(MarkupSafe(kvp.Value.ProcessName), selected),
                Cell($"[grey]{kvp.Value.Timestamp:yyyy-MM-dd HH:mm}[/]", selected));
        }
        return table;
    }

    static IRenderable BuildIgnoredPage(int visible)
    {
        var entries = _ignoredProcesses.OrderBy(x => x).ToList();
        if (_cursor >= entries.Count) _cursor = Math.Max(0, entries.Count - 1);

        int start = 0;
        if (entries.Count > visible)
            start = Math.Clamp(_cursor - visible / 2, 0, entries.Count - visible);

        var table = new Table().Border(TableBorder.Rounded).Expand();
        table.Title = new TableTitle("[bold yellow]IGNORED PROCESSES[/] [grey](X/Space remove · A add name)[/]");
        table.AddColumn(new TableColumn("").NoWrap());
        table.AddColumn(new TableColumn("Process").NoWrap());

        if (entries.Count == 0) { table.AddRow("", "[grey](none)[/]"); return table; }

        int shown = 0;
        for (int i = start; i < entries.Count && shown < visible; i++, shown++)
        {
            bool selected = i == _cursor;
            table.AddRow(
                Cell(selected ? "▶" : "", selected),
                Cell(MarkupSafe(entries[i]), selected));
        }
        return table;
    }

    static IRenderable BuildAlertsPage(int visible)
    {
        List<string> log;
        lock (_alertLock) { log = _alertLog.ToList(); }

        if (_cursor >= log.Count) _cursor = Math.Max(0, log.Count - 1);
        int start = 0;
        if (log.Count > visible)
            start = Math.Clamp(_cursor - visible / 2, 0, log.Count - visible);

        var table = new Table().Border(TableBorder.Rounded).Expand();
        table.Title = new TableTitle("[bold red]⚠ ALERT LOG[/] [grey](C clear)[/]");
        table.AddColumn(new TableColumn("").NoWrap());
        table.AddColumn(new TableColumn("Message").NoWrap());

        if (log.Count == 0) { table.AddRow("", "[grey](no alerts)[/]"); return table; }

        int shown = 0;
        for (int i = start; i < log.Count && shown < visible; i++, shown++)
        {
            bool selected = i == _cursor;
            table.AddRow(Cell(selected ? "▶" : "", selected), Cell(MarkupSafe(log[i]), selected));
        }
        return table;
    }

    static IRenderable BuildDomainsPage(int visible)
    {
        var entries = _domainCache.OrderBy(x => x.Key).ToList();
        if (_cursor >= entries.Count) _cursor = Math.Max(0, entries.Count - 1);

        int start = 0;
        if (entries.Count > visible)
            start = Math.Clamp(_cursor - visible / 2, 0, entries.Count - visible);

        var table = new Table().Border(TableBorder.Rounded).Expand();
        table.Title = new TableTitle("[bold blue]DOMAIN CACHE[/]");
        table.AddColumn(new TableColumn("").NoWrap());
        table.AddColumn(new TableColumn("IP").NoWrap());
        table.AddColumn(new TableColumn("Domain").NoWrap());

        if (entries.Count == 0) { table.AddRow("", "[grey](empty)[/]", ""); return table; }

        int shown = 0;
        for (int i = start; i < entries.Count && shown < visible; i++, shown++)
        {
            var kvp = entries[i];
            bool selected = i == _cursor;
            table.AddRow(
                Cell(selected ? "▶" : "", selected),
                Cell(Markup.Escape(kvp.Key), selected),
                Cell(MarkupSafe(kvp.Value), selected));
        }
        return table;
    }

    sealed class SystemSetting
    {
        public string   Name = "";
        public Func<bool> IsEnabled = () => false;
        public Action   Toggle = () => { };
    }

    static List<SystemSetting> BuildSystemSettings() => new()
    {
        new SystemSetting
        {
            Name = "App Telemetry",
            IsEnabled = SystemSettingsManager.IsTelemetryEnabled,
            Toggle = () =>
            {
                bool newState = !SystemSettingsManager.IsTelemetryEnabled();
                SystemSettingsManager.SetTelemetryEnabled(newState);
                ShowToast($"App Telemetry {(newState ? "enabled" : "disabled")}");
            }
        },
        new SystemSetting
        {
            Name = "Language Sync",
            IsEnabled = SystemSettingsManager.IsLanguageSyncEnabled,
            Toggle = () =>
            {
                bool newState = !SystemSettingsManager.IsLanguageSyncEnabled();
                SystemSettingsManager.SetLanguageSyncEnabled(newState);
                SystemSettingsManager.SetHardeningDefaultsEnabled(false);
                if (!newState) SystemSettingsManager.StopProcess("SettingSyncHost");
                ShowToast($"Language Sync {(newState ? "enabled" : "disabled")}");
            }
        },
        new SystemSetting
        {
            Name = "Windows Widgets",
            IsEnabled = SystemSettingsManager.IsWidgetsEnabled,
            Toggle = () =>
            {
                bool newState = !SystemSettingsManager.IsWidgetsEnabled();
                SystemSettingsManager.SetWidgetsEnabled(newState);
                SystemSettingsManager.SetHardeningDefaultsEnabled(false);
                if (!newState) SystemSettingsManager.StopProcess("Widgets");
                ShowToast($"Windows Widgets {(newState ? "enabled" : "disabled")}");
            }
        },
        new SystemSetting
        {
            Name = "SearchHost Box",
            IsEnabled = SystemSettingsManager.IsSearchHostEnabled,
            Toggle = () =>
            {
                bool newState = !SystemSettingsManager.IsSearchHostEnabled();
                SystemSettingsManager.SetSearchHostEnabled(newState);
                SystemSettingsManager.SetHardeningDefaultsEnabled(false);
                if (!newState) SystemSettingsManager.StopProcess("SearchHost");
                ShowToast($"SearchHost Box {(newState ? "enabled" : "disabled")}");
            }
        },
        new SystemSetting
        {
            Name = "SearchHost BG & Bing Search",
            IsEnabled = () => !SystemSettingsManager.IsSearchHostBackgroundAndBingDisabled(),
            Toggle = () =>
            {
                bool disable = SystemSettingsManager.IsSearchHostBackgroundAndBingDisabled() == false;
                SystemSettingsManager.SetSearchHostBackgroundAndBingDisabled(disable);
                SystemSettingsManager.SetHardeningDefaultsEnabled(false);
                if (disable) SystemSettingsManager.StopProcess("SearchHost");
                ShowToast($"SearchHost BG & Bing {(disable ? "disabled" : "enabled")}");
            }
        },
        new SystemSetting
        {
            Name = "StartMenuExperienceHost",
            IsEnabled = SystemSettingsManager.IsStartMenuExperienceHostEnabled,
            Toggle = () =>
            {
                bool newState = !SystemSettingsManager.IsStartMenuExperienceHostEnabled();
                SystemSettingsManager.SetStartMenuExperienceHostEnabled(newState);
                SystemSettingsManager.SetHardeningDefaultsEnabled(false);
                if (!newState) SystemSettingsManager.StopProcess("StartMenuExperienceHost");
                ShowToast($"StartMenuExperienceHost {(newState ? "enabled" : "disabled")}");
            }
        },
        new SystemSetting
        {
            Name = "ShellExperienceHost",
            IsEnabled = SystemSettingsManager.IsShellExperienceHostEnabled,
            Toggle = () =>
            {
                bool newState = !SystemSettingsManager.IsShellExperienceHostEnabled();
                SystemSettingsManager.SetShellExperienceHostEnabled(newState);
                SystemSettingsManager.SetHardeningDefaultsEnabled(false);
                if (!newState) SystemSettingsManager.StopProcess("ShellExperienceHost");
                ShowToast($"ShellExperienceHost {(newState ? "enabled" : "disabled")}");
            }
        },
        new SystemSetting
        {
            Name = "Block WebView2 Network",
            IsEnabled = SystemSettingsManager.IsWebView2Blocked,
            Toggle = () =>
            {
                bool block = !SystemSettingsManager.IsWebView2Blocked();
                SystemSettingsManager.SetWebView2Blocked(block);
                if (block)
                {
                    string? path = SystemSettingsManager.FindWebView2Path();
                    if (!string.IsNullOrEmpty(path) && FirewallManager.ApplyWebView2NetworkBlock(path))
                        ShowToast($"WebView2 outbound blocked ({path})");
                    else
                        ShowToast("Could not locate msedgewebview2.exe");
                }
                else
                {
                    FirewallManager.RemoveWebView2NetworkBlock();
                    ShowToast("WebView2 network block removed");
                }
            }
        },
    };

    static IRenderable BuildSystemPage(int visible)
    {
        var settings = BuildSystemSettings();
        if (_cursor >= settings.Count) _cursor = Math.Max(0, settings.Count - 1);

        int start = 0;
        if (settings.Count > visible)
            start = Math.Clamp(_cursor - visible / 2, 0, settings.Count - visible);

        string master = SystemSettingsManager.IsHardeningDefaultsEnabled()
            ? "[green]ON[/] [grey](defaults re-assert on startup; any manual toggle switches them off)[/]"
            : "[red]OFF[/] [grey](your manual choices are final)[/]";

        var table = new Table().Border(TableBorder.Rounded).Expand();
        table.Title = new TableTitle($"[bold cyan]SYSTEM SETTINGS[/]  [grey]hardening defaults:[/] {master}");
        table.AddColumn(new TableColumn("").NoWrap());
        table.AddColumn(new TableColumn("Setting").NoWrap());
        table.AddColumn(new TableColumn("State").NoWrap());

        int shown = 0;
        for (int i = start; i < settings.Count && shown < visible; i++, shown++)
        {
            var s = settings[i];
            bool selected = i == _cursor;
            bool enabled  = s.IsEnabled();
            table.AddRow(
                Cell(selected ? "▶" : "", selected),
                Cell(Markup.Escape(s.Name), selected),
                Cell(enabled ? "[green]Enabled[/]" : "[red]Disabled[/]", selected));
        }
        return table;
    }

    static IRenderable BuildStatusBar()
    {
        var sb = new StringBuilder();
        sb.Append($" [grey]connections:[/] [white]{_lastConnections.Count}[/]");

        if (_page is TuiPage.All or TuiPage.Outbound or TuiPage.Inbound)
        {
            var rows = VisibleConnections();
            sb.Append($"  [grey]shown:[/] [white]{rows.Count}[/]");
            if (!string.IsNullOrEmpty(_filterText))
                sb.Append($"  [cyan]/ {Markup.Escape(_filterText)}[/]");
        }

        if (DateTime.Now < _toastUntil)
            sb.Append($"   [bold yellow]› {MarkupSafe(_toast)}[/]");

        return new Markup(sb.ToString());
    }

    static IRenderable BuildFooter()
    {
        string hints = _mode switch
        {
            TuiMode.Filter  => "type to filter · Enter apply · Esc clear & exit",
            TuiMode.Detail  => "Esc close · live feed keeps updating behind this overlay",
            TuiMode.Confirm => "Enter/Y confirm · Esc/N cancel",
            TuiMode.Input   => "Enter save · Esc cancel",
            TuiMode.Help    => "Esc close",
            _ => _page switch
            {
                TuiPage.All or TuiPage.Outbound or TuiPage.Inbound =>
                    "↑↓ select · PgUp/PgDn page · 1-7 tabs · Enter details · B block · K kill · I ignore · / filter · S system · T strategy · R restore FW · H help · Q quit",
                TuiPage.Blocked => "↑↓ select · X/Space remove · A add IP · 1-7 tabs · S system · H help · Q quit",
                TuiPage.Ignored => "↑↓ select · X/Space remove · A add name · 1-7 tabs · S system · H help · Q quit",
                TuiPage.Alerts  => "↑↓ scroll · C clear · 1-7 tabs · H help · Q quit",
                TuiPage.Domains => "↑↓ scroll · 1-7 tabs · H help · Q quit",
                TuiPage.System  => "↑↓ select · Enter toggle · Esc back · H help · Q quit",
                _ => ""
            }
        };
        return new Rule($"[grey]{hints}[/]").Justify(Justify.Left);
    }

    static IRenderable BuildHelpPanel(int windowH, int windowW)
    {
        string etwStatus  = _etwTracker?.IsRunning == true ? "[green]Running[/]" : "[red]Stopped[/]";
        string strategy   = _etwTracker?.MonitoringStrategy.ToString() ?? "N/A";

        var markup =
            "[bold cyan]Navigation[/]\n" +
            "  [cyan]↑/↓[/] move cursor   [cyan]PgUp/PgDn[/] page   [cyan]1-7[/] tabs   [cyan]S[/] system settings\n" +
            "  [cyan]/[/] filter live feed (client-side)   [cyan]Esc[/] clear filter / close overlay\n\n" +
            "[bold cyan]Actions (on the selected row)[/]\n" +
            "  [cyan]Enter/P[/]  threat-intelligence detail\n" +
            "  [cyan]B[/]        firewall-block the connection's IP\n" +
            "  [cyan]K[/]        kill the process tree (confirm)\n" +
            "  [cyan]I[/]        ignore the process\n\n" +
            "[bold cyan]Lists & maintenance[/]\n" +
            "  [cyan]X/Space[/]  remove entry (Blocked / Ignored tabs)   [cyan]A[/] add entry\n" +
            "  [cyan]C[/]        clear alert log   [cyan]T[/] toggle monitoring strategy\n" +
            "  [cyan]R[/]        restore hardcoded firewall configuration (confirm)\n" +
            "  [cyan]Q[/]        quit\n\n" +
            "[bold cyan]Status[/]\n" +
            $"  ETW Tracing     : {etwStatus}\n" +
            $"  Active Strategy : [cyan]{Markup.Escape(strategy)}[/]\n" +
            $"  Blocked rules   : [red]{_blockedIPs.Count}[/]   Ignored: [yellow]{_ignoredProcesses.Count}[/]\n\n" +
            "[bold cyan]Files[/]\n" +
            $"  [grey]{BlockedFile}[/]   persisted block list (IP|process)   [grey]{IgnoredFile}[/]  ignored names\n" +
            $"  [grey]{FirewallRulePrefix}-…[/] rules visible in wf.msc → Outbound Rules";

        return new Panel(new Markup(markup)).Header("[bold]TCP Monitor Help[/]").Border(BoxBorder.Rounded).Expand();
    }

    #endregion

    #region Input Handling

    static void HandleKeyPress(ConsoleKeyInfo key)
    {
        switch (_mode)
        {
            case TuiMode.Help:
            case TuiMode.Detail:
                _mode = TuiMode.Feed;
                return;

            case TuiMode.Confirm:
                if (key.Key is ConsoleKey.Enter or ConsoleKey.Y)
                {
                    var action = _overlayAction;
                    _overlayAction = null;
                    _mode = TuiMode.Feed;
                    action?.Invoke();
                }
                else if (key.Key is ConsoleKey.Escape or ConsoleKey.N)
                {
                    _overlayAction = null;
                    _mode = TuiMode.Feed;
                }
                return;

            case TuiMode.Input:
                HandleInputKey(key);
                return;

            case TuiMode.Filter:
                HandleFilterKey(key);
                return;
        }

        // Feed mode
        switch (key.Key)
        {
            case ConsoleKey.Q:
                _running = false;
                break;

            case ConsoleKey.UpArrow:    MoveCursor(-1); break;
            case ConsoleKey.DownArrow:  MoveCursor(+1); break;
            case ConsoleKey.PageUp:     MoveCursor(-GetVisibleRows()); break;
            case ConsoleKey.PageDown:   MoveCursor(+GetVisibleRows()); break;
            case ConsoleKey.Home:       _cursor = 0; break;
            case ConsoleKey.End:        _cursor = int.MaxValue; break;

            case ConsoleKey.D1: SwitchPage(TuiPage.All);     break;
            case ConsoleKey.D2: SwitchPage(TuiPage.Outbound); break;
            case ConsoleKey.D3: SwitchPage(TuiPage.Inbound);  break;
            case ConsoleKey.D4: SwitchPage(TuiPage.Blocked);  break;
            case ConsoleKey.D5: SwitchPage(TuiPage.Ignored);  break;
            case ConsoleKey.D6: SwitchPage(TuiPage.Alerts);   break;
            case ConsoleKey.D7: SwitchPage(TuiPage.Domains);  break;

            case ConsoleKey.S:
                _pageBeforeSystem = _page;
                _page = TuiPage.System;
                _cursor = 0;
                break;

            case ConsoleKey.Enter:
            case ConsoleKey.P:
                if (_page is TuiPage.All or TuiPage.Outbound or TuiPage.Inbound) OpenDetail();
                break;

            case ConsoleKey.B:
                if (_page is TuiPage.All or TuiPage.Outbound or TuiPage.Inbound) BlockSelectedConnection();
                break;

            case ConsoleKey.K:
                if (_page is TuiPage.All or TuiPage.Outbound or TuiPage.Inbound) OpenKillConfirm();
                break;

            case ConsoleKey.I:
                if (_page is TuiPage.All or TuiPage.Outbound or TuiPage.Inbound) IgnoreSelectedProcess();
                break;

            case ConsoleKey.X:
            case ConsoleKey.Delete:
            case ConsoleKey.Spacebar:
                if (_page == TuiPage.Blocked) RemoveSelectedBlockedEntry();
                else if (_page == TuiPage.Ignored) RemoveSelectedIgnoredEntry();
                break;

            case ConsoleKey.A:
                if (_page == TuiPage.Blocked) OpenAddBlockedIp();
                else if (_page == TuiPage.Ignored) OpenAddIgnoredName();
                break;

            case ConsoleKey.C:
                if (_page == TuiPage.Alerts)
                {
                    lock (_alertLock) _alertLog.Clear();
                    _cursor = 0;
                    ShowToast("Alert log cleared");
                }
                break;

            case ConsoleKey.T: ToggleStrategy(); break;

            case ConsoleKey.R:
                if (_page is TuiPage.All or TuiPage.Outbound or TuiPage.Inbound)
                {
                    _overlayTitle = "RESTORE FIREWALL CONFIGURATION";
                    _overlayBody = "This will [red]disable all active firewall rules[/] and restore only the\n" +
                                   "hardcoded configuration rules.\n\nProceed?";
                    _overlayAction = () =>
                    {
                        try
                        {
                            FirewallManager.RestoreHardcodedConfiguration();
                            ShowToast("Firewall configuration restored");
                            LogAlert("INFO: Hardcoded firewall configuration restored");
                        }
                        catch (Exception ex) { ShowToast($"Restore failed: {ex.Message}"); }
                    };
                    _mode = TuiMode.Confirm;
                }
                break;

            case ConsoleKey.Escape:
                if (!string.IsNullOrEmpty(_filterText))
                {
                    _filterText = "";
                    ShowToast("Filter cleared");
                }
                break;

            case ConsoleKey.F1:
                _mode = TuiMode.Help;
                break;

            default:
                if (key.KeyChar == '/') { _mode = TuiMode.Filter; _inputValue = _filterText; }
                else if (key.KeyChar == '?') _mode = TuiMode.Help;
                break;
        }
    }

    static void HandleFilterKey(ConsoleKeyInfo key)
    {
        switch (key.Key)
        {
            case ConsoleKey.Enter:
                _filterText = _inputValue.Trim();
                _mode = TuiMode.Feed;
                _cursor = 0;
                break;
            case ConsoleKey.Escape:
                _inputValue = "";
                _filterText = "";
                _mode = TuiMode.Feed;
                break;
            case ConsoleKey.Backspace:
                if (_inputValue.Length > 0) _inputValue = _inputValue[..^1];
                break;
            default:
                if (!char.IsControl(key.KeyChar)) _inputValue += key.KeyChar;
                break;
        }
    }

    static void HandleInputKey(ConsoleKeyInfo key)
    {
        switch (key.Key)
        {
            case ConsoleKey.Enter:
                var action = _inputAction;
                var value  = _inputValue;
                _inputAction = null;
                _mode = TuiMode.Feed;
                action?.Invoke(value);
                break;
            case ConsoleKey.Escape:
                _inputAction = null;
                _mode = TuiMode.Feed;
                break;
            case ConsoleKey.Backspace:
                if (_inputValue.Length > 0) _inputValue = _inputValue[..^1];
                break;
            default:
                if (!char.IsControl(key.KeyChar)) _inputValue += key.KeyChar;
                break;
        }
    }

    static int GetVisibleRows()
    {
        try { return Math.Max(3, Console.WindowHeight - 10); }
        catch { return 15; }
    }

    static void MoveCursor(int delta)
    {
        _cursor = Math.Max(0, _cursor + delta);
    }

    static void SwitchPage(TuiPage page)
    {
        _page = page;
        _cursor = 0;
    }

    static void ToggleStrategy()
    {
        if (_etwTracker == null) return;
        var next = _etwTracker.MonitoringStrategy == ProcessMonitoringStrategy.ConnectionDriven
            ? ProcessMonitoringStrategy.ProcessStartEtw
            : ProcessMonitoringStrategy.ConnectionDriven;
        _etwTracker.SetMonitoringStrategy(next);
        LogAlert($"INFO: Switched monitoring strategy to {next}");
        ShowToast($"Strategy: {next}");
    }

    static void LogAlert(string message)
    {
        lock (_alertLock)
        {
            _alertLog.Add(message);
            if (_alertLog.Count > MaxAlertLogEntries) _alertLog.RemoveAt(0);
        }
    }

    #endregion

    #region Actions

    static TcpConnectionInfo? SelectedConnection()
    {
        var rows = VisibleConnections();
        if (_cursor < 0 || _cursor >= rows.Count) return null;
        return rows[_cursor];
    }

    static List<TcpConnectionInfo> VisibleConnections()
    {
        IEnumerable<TcpConnectionInfo> rows = _lastConnections;
        rows = _page switch
        {
            TuiPage.Outbound => rows.Where(c => c.LocalPort >= EphemeralPortFloor),
            TuiPage.Inbound  => rows.Where(c => c.LocalPort <  EphemeralPortFloor),
            _ => rows
        };
        if (!string.IsNullOrEmpty(_filterText))
        {
            string f = _filterText;
            rows = rows.Where(c =>
                c.ProcessName.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                c.RemoteIP.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                c.Domain.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                c.Geo.Contains(f, StringComparison.OrdinalIgnoreCase));
        }
        return rows.ToList();
    }

    static void BlockSelectedConnection()
    {
        var c = SelectedConnection();
        if (c == null) { ShowToast("Nothing selected"); return; }
        if (!IsValidIP(c.RemoteIP)) { ShowToast($"Invalid IP: {c.RemoteIP}"); return; }

        string ip = c.RemoteIP;
        bool added = FirewallManager.AddBlockRule(ip, c.ProcessName);
        if (!added) { ShowToast($"Failed to block {ip} (COM error — see crash.log)"); return; }

        _blockedIPs[ip] = new BlockedIPMetadata { ProcessName = c.ProcessName, Timestamp = DateTime.Now };

        // Re-blocking a default entry clears its opt-out so the default stays enforced.
        if (DefaultPolicy.IsDefaultBlockedKey(ip))
        {
            var removed = DefaultPolicy.LoadRemoved(ResolveBaseDir());
            if (removed.Remove(DefaultPolicy.BlockKey(ip)))
                DefaultPolicy.SaveRemoved(ResolveBaseDir(), removed);
        }

        RebuildBlockedProcessNames();
        SaveBlockList();
        ResetConnectionsToIp(ip);
        foreach (var conn in _lastConnections.Where(x => x.RemoteIP == ip))
            ResetConnectionsForPid(conn.PID);

        LogAlert($"BLOCKED {ip} ({c.ProcessName})");
        ShowToast($"Blocked {ip} ({c.ProcessName})");
    }

    static void OpenKillConfirm()
    {
        var c = SelectedConnection();
        if (c == null) { ShowToast("Nothing selected"); return; }
        if (c.PID <= 0) { ShowToast("Cannot kill an idle/system process"); return; }

        _overlayTitle = "TERMINATE PROCESS";
        _overlayBody  = $"Kill [red]{Markup.Escape(c.ProcessName)}[/] (PID {c.PID}) and its entire process tree?\n\n" +
                        "This cannot be undone.";
        _overlayAction = () => KillPid(c.PID);
        _mode = TuiMode.Confirm;
    }

    static void KillPid(int pid)
    {
        try
        {
            var process = Process.GetProcessById(pid);
            string name = process.ProcessName;
            process.Kill(entireProcessTree: true);
            LogAlert($"KILLED {name} (PID {pid}) and its tree");
            ShowToast($"Killed {name} (PID {pid})");
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 5)
        {
            ShowToast("Access denied — system or protected process");
        }
        catch (Exception ex)
        {
            ShowToast($"Kill failed: {ex.Message}");
        }
    }

    static void IgnoreSelectedProcess()
    {
        var c = SelectedConnection();
        if (c == null || string.IsNullOrWhiteSpace(c.ProcessName)) { ShowToast("Nothing selected"); return; }

        string name = c.ProcessName.ToLowerInvariant();
        if (_ignoredProcesses.Contains(name)) { ShowToast($"{c.ProcessName} is already ignored"); return; }

        _ignoredProcesses.Add(name);
        SaveIgnoreList();
        LogAlert($"INFO: Ignored {name}");
        ShowToast($"Ignored {name}");
    }

    static void RemoveSelectedBlockedEntry()
    {
        var keys = _blockedIPs.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase).Select(x => x.Key).ToList();
        if (_cursor < 0 || _cursor >= keys.Count) return;

        string key = keys[_cursor];
        _blockedIPs.Remove(key);

        if (IsValidIP(key)) FirewallManager.RemoveBlockRule(key);
        else FirewallManager.RemoveAppBlockRule(key);

        // Remember explicit opt-outs so default-policy seeding never re-adds them.
        if (DefaultPolicy.IsDefaultBlockedKey(key))
        {
            var removed = DefaultPolicy.LoadRemoved(ResolveBaseDir());
            if (removed.Add(DefaultPolicy.BlockKey(key)))
                DefaultPolicy.SaveRemoved(ResolveBaseDir(), removed);
        }

        RebuildBlockedProcessNames();
        SaveBlockList();
        LogAlert($"INFO: Removed block rule for {key}");
        ShowToast($"Removed {key}");
    }

    static void RemoveSelectedIgnoredEntry()
    {
        var entries = _ignoredProcesses.OrderBy(x => x).ToList();
        if (_cursor < 0 || _cursor >= entries.Count) return;

        string name = entries[_cursor];
        _ignoredProcesses.Remove(name);
        SaveIgnoreList();
        LogAlert($"INFO: Restored {name}");
        ShowToast($"Restored {name}");
    }

    static void OpenAddBlockedIp()
    {
        _inputPrompt = "IP address to block";
        _inputValue  = "";
        _inputAction = value =>
        {
            string ip = value.Trim();
            if (!IsValidIP(ip)) { ShowToast($"Invalid IP: {ip}"); return; }
            if (!FirewallManager.AddBlockRule(ip, "Manual")) { ShowToast($"Failed to block {ip}"); return; }

            _blockedIPs[ip] = new BlockedIPMetadata { ProcessName = "Manual", Timestamp = DateTime.Now };
            RebuildBlockedProcessNames();
            SaveBlockList();
            LogAlert($"BLOCKED {ip} (manual)");
            ShowToast($"Blocked {ip}");
        };
        _mode = TuiMode.Input;
    }

    static void OpenAddIgnoredName()
    {
        _inputPrompt = "Process name to ignore";
        _inputValue  = "";
        _inputAction = value =>
        {
            string name = value.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(name)) { ShowToast("Empty name"); return; }
            if (_ignoredProcesses.Contains(name)) { ShowToast($"{name} already ignored"); return; }

            _ignoredProcesses.Add(name);
            SaveIgnoreList();
            LogAlert($"INFO: Ignored {name}");
            ShowToast($"Ignored {name}");
        };
        _mode = TuiMode.Input;
    }

    static void OpenDetail()
    {
        var c = SelectedConnection();
        if (c == null) { ShowToast("Nothing selected"); return; }

        _overlayTitle = $"Threat Intelligence — {Markup.Escape(c.ProcessName)} (PID {c.PID})";
        _overlayBody  = BuildDetailBody(c);
        _mode = TuiMode.Detail;
    }

    static string BuildDetailBody(TcpConnectionInfo c)
    {
        string parentProcessName = "Unknown";
        string executablePath = "N/A";
        string signature = "Unsigned / Unknown";
        string lastModified = "N/A";

        IntPtr hProcess = IntPtr.Zero;
        try
        {
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, false, c.PID);
            if (hProcess == IntPtr.Zero)
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, c.PID);

            if (hProcess != IntPtr.Zero)
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (QueryFullProcessImageName(hProcess, 0, sb, ref size))
                    executablePath = sb.ToString();

                var pbi = new PROCESS_BASIC_INFORMATION();
                int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                if (status == 0)
                {
                    int parentPid = pbi.InheritedFromUniqueProcessId.ToInt32();
                    if (parentPid > 0)
                    {
                        try
                        {
                            using var parent = Process.GetProcessById(parentPid);
                            parentProcessName = $"{parent.ProcessName} (PID {parentPid})";
                        }
                        catch { parentProcessName = $"PID {parentPid} (Exited)"; }
                    }
                }
            }
        }
        catch
        {
            try { executablePath = Process.GetProcessById(c.PID).MainModule?.FileName ?? "N/A"; }
            catch { }
        }
        finally
        {
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }

        if (!string.IsNullOrEmpty(executablePath) && executablePath != "N/A" && File.Exists(executablePath))
        {
            try
            {
                var fileInfo = new FileInfo(executablePath);
                lastModified = fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");

                using var cert  = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(executablePath);
                using var cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert);
                string subject = cert2.Subject;
                if (subject.Contains("CN="))
                {
                    int start = subject.IndexOf("CN=") + 3;
                    int end = subject.IndexOf(',', start);
                    signature = end > start
                        ? "Signed by: " + subject.Substring(start, end - start)
                        : "Signed by: " + subject.Substring(start);
                }
                else signature = "Signed: " + cert2.Subject;
            }
            catch { signature = "Unsigned"; }
        }

        bool isBlocked = _blockedIPs.ContainsKey(c.RemoteIP) || _blockedProcessNames.Contains(c.ProcessName);

        return
            "[bold cyan]CONNECTION[/]\n" +
            $"  Remote : [red]{Markup.Escape(c.RemoteIP)}[/]:{c.RemotePort}   Local :{c.LocalPort}\n" +
            $"  Geo    : {MarkupSafe(c.Geo)}   Domain: {MarkupSafe(c.Domain)}\n" +
            $"  Up for : {MarkupSafe(c.Duration)}   Sent: [green]{MarkupSafe(c.TotalSent)}[/]   Recv: [yellow]{MarkupSafe(c.TotalReceived)}[/]\n" +
            $"  State  : {(isBlocked ? "[red]BLOCKED[/]" : "[green]allowed[/]")}{(c.IsGhosted ? " · [grey]ghosted (socket closing)[/]" : "")}\n\n" +
            "[bold cyan]PARENT PROCESS[/]\n" +
            $"  {MarkupSafe(parentProcessName)}\n\n" +
            "[bold cyan]DIGITAL SIGNATURE[/]\n" +
            $"  {MarkupSafe(signature)}\n\n" +
            "[bold cyan]LOCATION (EXECUTABLE PATH)[/]\n" +
            $"  {MarkupSafe(executablePath)}\n\n" +
            "[bold cyan]LAST MODIFIED[/]\n" +
            $"  {lastModified}";
    }

    #endregion
}
