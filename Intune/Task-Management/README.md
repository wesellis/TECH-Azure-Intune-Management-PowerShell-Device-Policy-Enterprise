# Task Management Scripts

This folder contains PowerShell scripts for managing Windows scheduled tasks, designed for enterprise deployment and automation scenarios.

## Scripts Overview

### Task Management Tools
- **Remove-ScheduledTask.ps1** - Template script for safely removing scheduled tasks with logging
- **ScheduledTaskTemplate.ps1** - Template for creating scheduled tasks from XML definitions

## Usage Examples

### Removing Scheduled Tasks
```powershell
# Customize the task name in the script
$TaskName = "YourTaskName"
.\Remove-ScheduledTask.ps1
```

### Creating Scheduled Tasks
```powershell
# 1. Export existing task XML (if using as template)
schtasks /query /tn "TaskName" /xml > task.xml

# 2. Customize the XML in ScheduledTaskTemplate.ps1
# 3. Update task name and run the script
.\ScheduledTaskTemplate.ps1
```

## Enterprise Deployment

### Intune Integration
These scripts can be deployed via:
- **Microsoft Intune** as Platform scripts
- **Group Policy** software installation
- **SCCM** application deployment
- **Azure Automation** runbooks

### Features
- **Administrator privilege verification** prevents unauthorized execution
- **Comprehensive logging** for audit and troubleshooting
- **Error handling** with graceful failures and rollback
- **Template-based approach** for easy customization

### Logging Location
All operations are logged to: `%TEMP%\ScriptLog_YYYYMMDD_HHMMSS.log`

## Customization Guidelines

### Remove-ScheduledTask.ps1
1. Modify the `$TaskName` variable with your target task
2. Test in lab environment before production deployment
3. Verify task existence before deployment to avoid warnings

### ScheduledTaskTemplate.ps1
1. Replace the XML template with your task definition
2. Export existing tasks using: `schtasks /query /tn "TaskName" /xml`
3. Update the `$TaskName` variable to match your XML
4. Test XML validity before deployment

## Security Considerations

- Scripts require administrative privileges
- Task definitions should follow principle of least privilege
- Validate XML content to prevent injection attacks
- Monitor execution logs for security compliance

---
**Author**: Wesley Ellis | **Email**: wes@wesellis.com | **Website**: wesellis.com
