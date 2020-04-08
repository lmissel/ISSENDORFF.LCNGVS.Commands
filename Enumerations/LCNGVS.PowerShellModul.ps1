$Source = @"
namespace LCNGVS.PowerShellModul
{
    public enum UserRight
    {
        AccessControlManagementRight,
        AccessControlVisualizationRight,
        BackUpManagementRight,
        ChangeOwnUserDataRight,
        CommonManagementRight,
        ConnectionManagementRight,
        ImageManagementRight,
        LogsViewRight,
        MacroManagementRight,
        MonitoringManagementRight,
        NavigationControlViewRight,
        PersonManagementRight,
        ProjectReleaseRight,
        TimerManagementRight,
        UserManagementRight,
        VisualizationEditorRight,
        VisualizationRight
    }

    public enum Theme
    {
        Standard,
        ISSENDORFF
    }
}
"@

Add-Type -TypeDefinition $Source