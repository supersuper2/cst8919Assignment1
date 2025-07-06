#  Secure Flask App with Auth0, Azure, and Logging

Demo Link: https://youtu.be/DhNa481Me5g

---

## 🛠️ Setup Steps

### 1. ✅ Auth0 Configuration

1. Go to [Auth0 Dashboard](https://manage.auth0.com)
2. Create a new **Regular Web Application** and setup a the **Application Settings**:
3. Copy the following values from your Auth0 app:
   - Domain → `AUTH0_DOMAIN`
   - Client ID → `AUTH0_CLIENT_ID`
   - Client Secret → `AUTH0_CLIENT_SECRET`
---

### 2. Azure Web App Services 
1. Go to [Azure Portal](https://portal.azure.com)
2. Create a new **App Service**:
   - Runtime stack: Python 3.10+
   - OS: Linux
   - Region: Canada Central (or your preference)
3. Enable **Log Analytics** when creating the App Service
4. Once created, go to **Deployment Center** → **GitHub**
5. Authorize GitHub and choose:
   - Organization & Repository
   - Branch: `main`
6. Confirm and complete the setup

### 3. Create a Log Analytics Workspace
1. Go to [Azure Portal](https://portal.azure.com)
2. Search for "Log Analytics workspaces" and click Create:
   - Name: MyLogsWorkspace (or any name)
   - Region: Same as your App Service (e.g., Canada Central)
4. Click Review + Create → then Create

#### 4. In Log Analytics
1. Go to your App Service
2. Under Monitoring, click "Diagnostic settings"
3. Click “+ Add diagnostic setting”
4. Name it (e.g., SendToLogs) and Check:
   - AppServiceConsoleLogs
   - AppServiceAppLogs
5. Choose your Log Analytics workspace (created in Step 1)
6. Click Save

---
---

## 📋 Logging & Detection Logic

## 📊 KQL Query for Suspicious Behavior

Detects users who accessed `/protected` more than 10 times in the last 15 minutes:

```kql
AppServiceConsoleLogs
| where TimeGenerated > ago(15m)
| where ResultDescription contains "USER_ACTIVITY"
| where ResultDescription contains "protected_route_access"
| extend data = parse_json(substring(ResultDescription, indexof(ResultDescription, "{")))
| where isnotempty(data.user_id)
| summarize AccessCount = count() by
    user_id = tostring(data.user_id),
    bin(TimeGenerated, 15m)
| project TimeGenerated, user_id, AccessCount
| order by AccessCount desc
```

---

## 🚨 Alert Rule (Azure Monitor)

- **Target**: Log Analytics Workspace
- **Condition**: Run above KQL query
- **Frequency**: Every 5 minutes
- **Alert Criteria**: If **results ≥ 1**
- **Severity**: 3 (Low)
- **Action Group**: Email notification to your team
---
