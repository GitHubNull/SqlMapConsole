package ui.panel;

import burp.IHttpRequestResponse;
import entities.OptionsCommandLine;
import models.ScanTaskTableModel;
import sqlmapApi.SqlMapApiClient;
import ui.panel.subPanel.CommandLineManagerPanel;
import ui.panel.subPanel.SqlMapServiceTabPanel;
import ui.panel.subPanel.TaskHistory;

import javax.swing.*;
import java.util.List;

public class ConsoleTab extends JTabbedPane {
    TaskHistory taskHistory;
    CommandLineManagerPanel commandLineManagerPanel;
    SqlMapServiceTabPanel sqlMapServiceTabPanel;

    public ConsoleTab() {
        taskHistory = new TaskHistory();
        commandLineManagerPanel = new CommandLineManagerPanel();
        sqlMapServiceTabPanel = new SqlMapServiceTabPanel();


        add("任务列表", taskHistory);
        add("命令行参数列表", commandLineManagerPanel);
        add("后台服务", sqlMapServiceTabPanel);

        setComponentAt(0, taskHistory);
        setComponentAt(1, commandLineManagerPanel);
        setComponentAt(2, sqlMapServiceTabPanel);
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
