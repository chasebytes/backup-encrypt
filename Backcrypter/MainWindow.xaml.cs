using Backcrypter.Core;
using Microsoft.Win32;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Controls;
using System.Windows.Media;

namespace Backcrypter;

public partial class MainWindow : Window
{
    private readonly IArchiveService service = new ArchiveService();
    private CancellationTokenSource? operation;
    private string? lastMessage;
    private string PasswordValue => ShowPassword.IsChecked == true ? VisiblePassword.Text : password.Password;
    private string ConfirmationValue => ShowPassword.IsChecked == true ? VisibleConfirmation.Text : confirmation.Password;
    private string RestorePasswordValue => ShowRestorePassword.IsChecked == true ? VisibleRestorePassword.Text : RestorePassword.Password;

    private void WorkflowChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.Source != WorkflowTabs || operation is not null || status is null) return;
        status.Text = WorkflowTabs.SelectedIndex == 0
            ? "Ready. Select files and folders to protect."
            : "Ready. Choose an archive, a new destination folder, and its original credentials.";
    }

    private void ChangeTheme(object sender, RoutedEventArgs e)
    {
        string[] keys = ["PageBrush", "CardBrush", "InputBrush", "TextBrush", "MutedBrush", "BorderBrush", "ButtonBrush", "HoverBrush", "AccentBrush"];
        string[] colors = DarkMode.IsChecked == true
            ? ["#111722", "#1B2432", "#121A27", "#EDF2FA", "#AFBDD1", "#41516A", "#293A52", "#364E6E", "#8FC2FF"]
            : ["#F3F5F9", "#FFFFFF", "#FFFFFF", "#202B3D", "#58657A", "#BCC8D8", "#E2E9F2", "#D1DEEE", "#3463A4"];
        for (int i = 0; i < keys.Length; i++)
            Application.Current.Resources[keys[i]] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colors[i]));
    }

    private void ProtectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CreateKeyPanel is not null) CreateKeyPanel.IsEnabled = ProtectionMode.SelectedIndex == 1;
    }

    private void BrowseRestoreArchive(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Backcrypter archive|*.bcrypt|All files|*.*", Title = "Select archive to restore" };
        if (dialog.ShowDialog(this) == true) RestoreArchivePath.Text = dialog.FileName;
    }

    private void BrowseRestoreDestination(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose parent directory for the new restore folder" };
        if (dialog.ShowDialog(this) != true) return;
        RestoreDestination.Text = Path.Combine(dialog.FolderName, "restored-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"));
    }

    private void ChooseRestoreKey(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Backcrypter key|*.bkey|All files|*.*" };
        if (dialog.ShowDialog(this) == true) RestoreKeyFile.Text = dialog.FileName;
    }

    private void ClearRestoreKey(object sender, RoutedEventArgs e) => RestoreKeyFile.Clear();

    private void ToggleRestorePassword(object sender, RoutedEventArgs e)
    {
        bool show = ShowRestorePassword.IsChecked == true;
        if (show) VisibleRestorePassword.Text = RestorePassword.Password;
        else
        {
            RestorePassword.Password = VisibleRestorePassword.Text;
            VisibleRestorePassword.Clear();
        }
        RestorePassword.Visibility = show ? Visibility.Collapsed : Visibility.Visible;
        VisibleRestorePassword.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
    }

    public MainWindow()
    {
        InitializeComponent();
        Closing += (_, e) =>
        {
            if (operation is null) return;
            e.Cancel = true;
            CancelOperation(this, new RoutedEventArgs());
            Log("Cancelling operation. Close the window after cleanup completes.");
        };
        Log("AES-256-GCM • encrypted filenames • source files are retained");
    }

    private void RemoveSources(object sender, RoutedEventArgs e)
    {
        foreach (var item in sources.SelectedItems.Cast<string>().ToArray()) sources.Items.Remove(item);
    }
    private void ClearSources(object sender, RoutedEventArgs e) => sources.Items.Clear();
    private void ClearKey(object sender, RoutedEventArgs e) => keyFile.Clear();
    private async void CreateClicked(object sender, RoutedEventArgs e) => await CreateArchive();
    private async void RestoreClicked(object sender, RoutedEventArgs e) => await RestoreArchive();
    private void CancelOperation(object sender, RoutedEventArgs e)
    {
        operation?.Cancel();
        cancel.IsEnabled = false;
        status.Text = "Cancelling and cleaning up…";
    }
    private void TogglePassword(object sender, RoutedEventArgs e)
    {
        if (ShowPassword.IsChecked == true)
        {
            VisiblePassword.Text = password.Password;
            VisibleConfirmation.Text = confirmation.Password;
        }
        else
        {
            password.Password = VisiblePassword.Text;
            confirmation.Password = VisibleConfirmation.Text;
            VisiblePassword.Clear();
            VisibleConfirmation.Clear();
        }
        password.Visibility = confirmation.Visibility = ShowPassword.IsChecked == true ? Visibility.Collapsed : Visibility.Visible;
        VisiblePassword.Visibility = VisibleConfirmation.Visibility = ShowPassword.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }
    private void AddFiles(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Multiselect = true, Title = "Select files to back up" };
        if (dialog.ShowDialog(this) == true) AddSources(dialog.FileNames);
    }
    private void AddFolders(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Multiselect = true, Title = "Select folders to back up" };
        if (dialog.ShowDialog(this) == true) AddSources(dialog.FolderNames);
    }
    private void AddSources(IEnumerable<string> paths)
    {
        foreach (string path in paths) if (!sources.Items.Cast<string>().Contains(path, StringComparer.OrdinalIgnoreCase)) sources.Items.Add(path);
    }
    private void ChooseKey(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Backcrypter key|*.bkey|All files|*.*" };
        if (dialog.ShowDialog(this) == true) keyFile.Text = dialog.FileName;
    }
    private void GenerateKey(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter = "Backcrypter key|*.bkey", DefaultExt = "bkey", FileName = "backup-key.bkey" };
        if (dialog.ShowDialog(this) != true) return;
        try { ArchiveService.GenerateKeyFile(dialog.FileName); keyFile.Text = dialog.FileName; Log("Key file generated. Keep a separate safe copy; do not store it alongside the cloud archive."); }
        catch (Exception ex) { ShowError(ex.Message); }
    }
    private ArchiveCredentials Credentials() => new(PasswordValue, ProtectionMode.SelectedIndex == 1 ? keyFile.Text : null);
    private async Task CreateArchive()
    {
        if (sources.Items.Count == 0) { ShowError("Add at least one file or folder."); return; }
        if (PasswordValue.Length < 12) { ShowError("Use a password or passphrase of at least 12 characters."); return; }
        if (PasswordValue != ConfirmationValue) { ShowError("The passwords do not match."); return; }
        if (ProtectionMode.SelectedIndex == 1 && string.IsNullOrWhiteSpace(keyFile.Text))
        { ShowError("Choose or generate a key file for password + key file protection."); return; }
        var dialog = new SaveFileDialog { Filter = "Backcrypter archive|*.bcrypt", DefaultExt = "bcrypt", FileName = "backup-" + DateTime.Now.ToString("yyyy-MM-dd") + ".bcrypt" };
        if (dialog.ShowDialog(this) != true) return;
        var selected = sources.Items.Cast<string>().ToArray();
        var credentials = Credentials();
        var factor = new[] { PasswordWorkFactor.Standard, PasswordWorkFactor.Strong, PasswordWorkFactor.Maximum }[work.SelectedIndex];
        await Run((p, ct) => service.CreateAsync(selected, dialog.FileName, credentials, factor, p, ct));
    }
    private async Task RestoreArchive()
    {
        if (!File.Exists(RestoreArchivePath.Text)) { ShowError("Choose an existing encrypted archive."); return; }
        if (string.IsNullOrWhiteSpace(RestoreDestination.Text)) { ShowError("Choose a new folder for restored files."); return; }
        if (string.IsNullOrWhiteSpace(RestorePasswordValue)) { ShowError("Enter the archive password in the Restore tab."); return; }
        string archive = RestoreArchivePath.Text;
        string destination = RestoreDestination.Text;
        var credentials = new ArchiveCredentials(RestorePasswordValue, string.IsNullOrEmpty(RestoreKeyFile.Text) ? null : RestoreKeyFile.Text);
        if (await Run((p, ct) => service.RestoreAsync(archive, destination, credentials, p, ct)))
            Log("Restored to: " + destination);
    }
    private async Task<bool> Run(Func<IProgress<ArchiveProgress>, CancellationToken, Task> action)
    {
        operation = new();
        var currentOperation = operation;
        CreatePanel.IsEnabled = RestorePanel.IsEnabled = false;
        cancel.IsEnabled = true;
        progressBar.Value = 0;
        progressBar.IsIndeterminate = true;
        lastMessage = null;
        try
        {
            // Throttle before posting to the UI thread, so large backups cannot flood its queue.
            var uiProgress = new Progress<ArchiveProgress>(p =>
            {
                if (operation != currentOperation || currentOperation.IsCancellationRequested) return;
                status.Text = $"{p.Message}   {p.BytesProcessed / 1048576d:N1} MiB";
                if (p.TotalBytes is > 0)
                {
                    progressBar.IsIndeterminate = false;
                    progressBar.Value = (int)Math.Clamp(p.BytesProcessed * 100d / p.TotalBytes.Value, 0, 100);
                }
                if (lastMessage != p.Message) { Log(p.Message); lastMessage = p.Message; }
            });
            await action(new ThrottledProgress(uiProgress), operation.Token);
            status.Text = "Completed successfully.";
            progressBar.IsIndeterminate = false;
            progressBar.Value = 100;
            return true;
        }
        catch (OperationCanceledException) { status.Text = "Cancelled."; Log("Cancelled. Temporary output cleaned up."); }
        catch (CryptographicException) { ShowError("Authentication failed: wrong password/key file, or damaged archive. No restore folder was published."); }
        catch (Exception ex) { ShowError(ex.Message); }
        finally
        {
            operation.Dispose(); operation = null;
            CreatePanel.IsEnabled = RestorePanel.IsEnabled = true;
            cancel.IsEnabled = false;
            progressBar.IsIndeterminate = false;
            password.Clear(); confirmation.Clear(); VisiblePassword.Clear(); VisibleConfirmation.Clear();
            RestorePassword.Clear(); VisibleRestorePassword.Clear();
        }
        return false;
    }
    private sealed class ThrottledProgress(IProgress<ArchiveProgress> target) : IProgress<ArchiveProgress>
    {
        private long last;
        public void Report(ArchiveProgress value)
        {
            long now = Environment.TickCount64;
            if (now - last < 100 && value.BytesProcessed != value.TotalBytes) return;
            last = now;
            target.Report(value);
        }
    }
    private void Log(string message)
    {
        if (new TextRange(console.Document.ContentStart, console.Document.ContentEnd).Text.Length > 100_000) console.Document.Blocks.Clear();
        console.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        console.ScrollToEnd();
    }
    private void ShowError(string message) { status.Text = "Operation could not complete."; Log(message); MessageBox.Show(this, message, "Backcrypter", MessageBoxButton.OK, MessageBoxImage.Warning); }
}

