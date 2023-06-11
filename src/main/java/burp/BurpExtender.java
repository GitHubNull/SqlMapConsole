package burp;

import controller.ContextMenuFactory;
import entities.OptionsCommandLine;
import models.ScanTaskTableModel;
import org.apache.commons.lang.StringUtils;
import sqlmapApi.SqlMapApiClient;
import ui.panel.ConsoleTab;
import utils.GlobalStaticVariables;
import utils.MessageUtil;
import utils.OldSqlmapApiSubProcessKillHelper;
import utils.SerializeUtil;

import java.awt.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public final static String NAME = "SqlMapConsole";

    public static ConsoleTab consoleTab;

    private final static String PYTHON_EXEC_PATH_CONFIG_VAR = "PYTHON_EXEC_PATH";
    private final static String SQLMAP_API_PATH_CONFIG_VAR = "SQLMAP_API_PATH";
    private final static String SQLMAP_API_PORT_CONFIG_VAR = "SQLMAP_API_PORT";
    private final static String TMP_REQUEST_FILE_DIR_PATH_CONFIG_VAR = "TMP_REQUEST_FILE_DIR_PATH";
    public final static boolean debug = true;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.setExtensionName(NAME);

        consoleTab = new ConsoleTab();

        callbacks.addSuiteTab(this);

        callbacks.registerContextMenuFactory(new ContextMenuFactory());
        callbacks.registerExtensionStateListener(this);

        loadExtenderConfig();

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

    public static ConsoleTab getConsoleTab() {
        return consoleTab;
    }


    private void saveSqlMapApiServiceConfig() {
        callbacks.saveExtensionSetting(PYTHON_EXEC_PATH_CONFIG_VAR, GlobalStaticVariables.PYTHON_EXEC_PATH);
        callbacks.saveExtensionSetting(SQLMAP_API_PATH_CONFIG_VAR, GlobalStaticVariables.SQLMAP_API_PATH);
        callbacks.saveExtensionSetting(SQLMAP_API_PORT_CONFIG_VAR, Integer.toString(GlobalStaticVariables.SQLMAP_API_PORT));
        callbacks.saveExtensionSetting(TMP_REQUEST_FILE_DIR_PATH_CONFIG_VAR, GlobalStaticVariables.TMP_REQUEST_FILE_DIR_PATH);
    }

    private void saveCommandLines() {
        List<OptionsCommandLine> optionsCommandLineList = consoleTab.getOptionsCommandLineList();
        List<String> objectStrList = new ArrayList<>();
        for (OptionsCommandLine optionsCommandLine : optionsCommandLineList) {
            try {
                String objectStr = SerializeUtil.serialize(optionsCommandLine);
                objectStrList.add(objectStr);
            } catch (Exception e) {
                stderr.println(e);
            }
        }

        String finalExtenderCommandLinesStr = String.join(GlobalStaticVariables.EXTENDER_CONFIG_SEPARATOR, objectStrList);
        callbacks.saveExtensionSetting(GlobalStaticVariables.COMMAND_LINES_STR_VAR, finalExtenderCommandLinesStr);
    }

    private void saveExtenderConfig() {
        saveSqlMapApiServiceConfig();
        saveCommandLines();
    }

    private void loadSqlMapApiServiceConfig() {
        String tmp_PYTHON_EXEC_PATH = callbacks.loadExtensionSetting(PYTHON_EXEC_PATH_CONFIG_VAR);
        if (null != tmp_PYTHON_EXEC_PATH && !tmp_PYTHON_EXEC_PATH.trim().isEmpty()) {
            GlobalStaticVariables.PYTHON_EXEC_PATH = tmp_PYTHON_EXEC_PATH;
        }

        String tmp_SQLMAP_API_PATH = callbacks.loadExtensionSetting(SQLMAP_API_PATH_CONFIG_VAR);
        if (null != tmp_SQLMAP_API_PATH && !tmp_SQLMAP_API_PATH.trim().isEmpty()) {
            GlobalStaticVariables.SQLMAP_API_PATH = tmp_SQLMAP_API_PATH;
        }

        String tmp_SQLMAP_API_PORT = callbacks.loadExtensionSetting(SQLMAP_API_PORT_CONFIG_VAR);
        if (null != tmp_SQLMAP_API_PORT && !tmp_SQLMAP_API_PORT.trim().isEmpty()) {
            if (StringUtils.isNumeric(tmp_SQLMAP_API_PORT)) {
                int port = Integer.parseInt(tmp_SQLMAP_API_PORT);
                if (0 < port && port < 65535) {
                    GlobalStaticVariables.SQLMAP_API_PORT = port;
                }

            } else {
                GlobalStaticVariables.SQLMAP_API_PORT = 5678;
            }
        }

        String tmp_TMP_REQUEST_FILE_DIR_PATH = callbacks.loadExtensionSetting(TMP_REQUEST_FILE_DIR_PATH_CONFIG_VAR);
        if (null != tmp_TMP_REQUEST_FILE_DIR_PATH && !tmp_TMP_REQUEST_FILE_DIR_PATH.trim().isEmpty()) {
            GlobalStaticVariables.TMP_REQUEST_FILE_DIR_PATH = tmp_TMP_REQUEST_FILE_DIR_PATH;
        }

        consoleTab.getSqlMapServiceTabPanel().flushConfig();
    }

    private void loadCommandLines() {
        String tmp = callbacks.loadExtensionSetting(GlobalStaticVariables.COMMAND_LINES_STR_VAR);
        if (null == tmp || tmp.trim().isEmpty()) {
//            stderr.println("loadCommandLines: null == tmp || tmp.trim().isEmpty() 193");
            return;
        }

        String[] objectStrArray = tmp.split(GlobalStaticVariables.EXTENDER_CONFIG_SEPARATOR);

        boolean configDefaultFlag = false;
        for (String objectStr : objectStrArray) {
            try {
                OptionsCommandLine optionsCommandLine = SerializeUtil.deserialize(objectStr);
                if (null == optionsCommandLine) {
                    continue;
                }
                if (!configDefaultFlag && Boolean.TRUE.equals(optionsCommandLine.getWasDefault())) {
                    GlobalStaticVariables.DEFAULT_COMMAND_LINE_STR = optionsCommandLine.getCommandLineStr();
                    configDefaultFlag = true;
                }
                consoleTab.getcommandLineManagerPanel().getTableModel().addOptionsCommandLine(optionsCommandLine);
            } catch (Exception e) {
                stderr.println(e);
            }
        }
    }

    private void loadExtenderConfig() {
        loadSqlMapApiServiceConfig();
        loadCommandLines();
    }

    @Override
    public void extensionUnloaded() {
        saveExtenderConfig();
        consoleTab.getSqlMapServiceTabPanel().stopService();
        OldSqlmapApiSubProcessKillHelper.kill();
        stdout.println("extensionUnloaded...");
    }

    public static int addScanTaskToTaskHistory(IHttpRequestResponse httpRequestResponse, String taskName, String taskId, String cmdLine) {
        return consoleTab.addNewScanTask(httpRequestResponse, taskName, taskId, cmdLine);
    }

    public static List<OptionsCommandLine> getScanTaskArgsListFromTaskArgPanel() {
        return consoleTab.getOptionsCommandLineList();
    }

    public static void flushScanTaskStatus() {
        consoleTab.getTaskHistory().flushScanTaskStatus();
    }

    public static void updateI18n(MessageUtil messageUtil) {
        GlobalStaticVariables.EX_MSG = messageUtil;
        consoleTab.updateI18n(messageUtil);
    }

    public final static void debugInfo(String msg) {
        if (debug) {
            stdout.println(msg);
        }
    }

    public final static void debugError(String msg) {
        if (debug) {
            stderr.println(msg);
        }
    }
}
