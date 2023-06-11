package ui.panel;

import burp.IHttpRequestResponse;
import entities.OptionsCommandLine;
import models.ScanTaskTableModel;
import sqlmapApi.SqlMapApiClient;
import ui.panel.subPanel.CommandLineManagerPanel;
import ui.panel.subPanel.GlobalConfigPanel;
import ui.panel.subPanel.SqlMapServiceTabPanel;
import ui.panel.subPanel.TaskHistory;
import utils.GlobalStaticVariables;
import utils.MessageUtil;

import javax.swing.*;
import java.util.List;

public class ConsoleTab extends JTabbedPane {
    TaskHistory taskHistory;
    CommandLineManagerPanel commandLineManagerPanel;
    SqlMapServiceTabPanel sqlMapServiceTabPanel;
    GlobalConfigPanel globalConfigPanel;


    public ConsoleTab() {
        taskHistory = new TaskHistory();
        commandLineManagerPanel = new CommandLineManagerPanel();
        sqlMapServiceTabPanel = new SqlMapServiceTabPanel();
        globalConfigPanel = new GlobalConfigPanel();

        MessageUtil messageUtil = GlobalStaticVariables.EX_MSG;


        add(messageUtil.getMsg("taskHistory"), taskHistory);
        add(messageUtil.getMsg("commandLineList"), commandLineManagerPanel);
        add(messageUtil.getMsg("sqlmapApiService"), sqlMapServiceTabPanel);
        add(messageUtil.getMsg("globalConfigPanel"), globalConfigPanel);

        setComponentAt(0, taskHistory);
        setComponentAt(1, commandLineManagerPanel);
        setComponentAt(2, sqlMapServiceTabPanel);
        setComponentAt(3, globalConfigPanel);
    }

    private void updateSelfI18n(MessageUtil messageUtil) {
        setTitleAt(0, messageUtil.getMsg("taskHistory"));
        setTitleAt(1, messageUtil.getMsg("commandLineList"));
        setTitleAt(2, messageUtil.getMsg("sqlmapApiService"));
        setTitleAt(3, messageUtil.getMsg("globalConfigPanel"));
    }

    public void updateI18n(MessageUtil messageUtil) {
        updateSelfI18n(messageUtil);

        commandLineManagerPanel.updateI18n(messageUtil);
        taskHistory.updateI18n();
        sqlMapServiceTabPanel.updateI18n();
    }

    public TaskHistory getTaskHistory() {
        return taskHistory;
    }

    public ScanTaskTableModel getScanTaskTableModel() {
        return taskHistory.getScanTaskTableModel();
    }

    public int addNewScanTask(IHttpRequestResponse httpRequestResponse, String taskName, String taskId, String cmdLine) {
        return taskHistory.addNewScanTask(httpRequestResponse, taskName, taskId, cmdLine);
    }


    public List<OptionsCommandLine> getOptionsCommandLineList() {
        return commandLineManagerPanel.getOptionsCommandLineList();
    }

    public SqlMapServiceTabPanel getSqlMapServiceTabPanel() {
        return sqlMapServiceTabPanel;
    }

    public SqlMapApiClient getSqlMapApiClient() {
        return sqlMapServiceTabPanel.getSqlMapApiClient();
    }

    public CommandLineManagerPanel getcommandLineManagerPanel() {
        return commandLineManagerPanel;
    }
}
