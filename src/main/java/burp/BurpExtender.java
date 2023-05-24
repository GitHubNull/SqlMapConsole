package burp;

import controller.ContextMenuFactory;
import entities.ScanTask;
import entities.ScanTaskOptionsCommandLine;
import models.ScanTaskTableModel;
import okhttp3.Call;
import sqlmapApi.SqlMapApi;
import sqlmapApi.SqlMapApiClient;
import sqlmapApi.requestsBody.ScanOptions;
import ui.panel.ConsoleTab;
import utils.OldSqlmapApiSubProcessKillHelper;

import java.awt.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public final static String NAME = "SqlMapConsole";

    public static ConsoleTab consoleTab;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.setExtensionName(NAME);

        consoleTab = new ConsoleTab();

        callbacks.addSuiteTab(this);

//        ContextFactory contextFactory = new ContextFactory();
        callbacks.registerContextMenuFactory(new ContextMenuFactory());
        OldSqlmapApiSubProcessKillHelper.kill();
    }

    public static synchronized void startScanTask(String taskName, String commandLineStr, IHttpRequestResponse httpRequestResponse) throws IOException {
        if (null == taskName || null == commandLineStr || null == httpRequestResponse) {
            return;
        }

        if (taskName.trim().isEmpty() || commandLineStr.trim().isEmpty()) {
            return;
        }

        consoleTab.getSqlMapApiClient().startScanTask(taskName, commandLineStr, httpRequestResponse);
    }

    public static ScanTaskTableModel getScanTaskTableModel() {
        return consoleTab.getScanTaskTableModel();
    }


    public static Call deleteScanTaskFromSqlMapApiService(String taskId) throws IOException {
        return consoleTab.getSqlMapApiClient().deleteScanTask(taskId);
    }

    public static Call stopScanTaskInSqlMapApiService(String taskId) {
        return consoleTab.getSqlMapApiClient().stopScanTask(taskId);
    }

    public static Call killScanTaskInSqlMapApiService(String taskId) {
        return consoleTab.getSqlMapApiClient().killScanTask(taskId);
    }


    public static Call updateScanTaskInSqlMapApiService(String taskId, ScanOptions scanOptions) throws IOException {
        return consoleTab.getSqlMapApiClient().updateScanTask(taskId, scanOptions);
    }

    public static Call getScanTaskStatusFromSqlMapApiService(String taskId) {
        return consoleTab.getSqlMapApiClient().getScanTaskStatus(taskId);
    }

    public static Call getScanTaskDataFromSqlMapApiService(String taskId) {
        return consoleTab.getSqlMapApiClient().getScanTaskData(taskId);
    }

    public static Call getScanTaskLogRangeFromSqlMapApiService(String taskId, int startIndex, int endIndex) {
        return consoleTab.getSqlMapApiClient().getScanTaskLogRange(taskId, startIndex, endIndex);
    }

    public static Call getScanTaskLogFromSqlMapApiService(String taskId) {
        return consoleTab.getSqlMapApiClient().getScanTaskLog(taskId);
    }

    public static SqlMapApi getSqlMapApi() {
        return consoleTab.getSqlMapApi();
    }

    public static SqlMapApiClient getSqlMapApiClient() {
        return consoleTab.getSqlMapApiClient();
    }

    @Override
    public String getTabCaption() {
        return NAME;
    }

    @Override
    public Component getUiComponent() {
        return consoleTab;
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("extensionUnloaded...");
        consoleTab.getSqlMapServiceTabPanel().stopService();
        OldSqlmapApiSubProcessKillHelper.kill();
    }

    public static void addScanTaskToTaskHistoryPanel(ScanTask scanTask) {
        consoleTab.addNewScanTask(scanTask);
    }

    public static int addScanTaskToTaskHistory(IHttpRequestResponse httpRequestResponse, String taskName, String taskId) {
        return consoleTab.addNewScanTask(httpRequestResponse, taskName, taskId);
    }

    public static int getScanTaskIdFromTaskHistoryPanel() {
        return consoleTab.getNewScanTaskId();
    }

    public static List<ScanTaskOptionsCommandLine> getScanTaskArgsListFromTaskArgPanel() {
        return consoleTab.getScanTaskArgsList();
    }

    public static ConsoleTab getConsoleTab() {
        return consoleTab;
    }
}
