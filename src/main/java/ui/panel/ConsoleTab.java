package ui.panel;

import burp.IHttpRequestResponse;
import entities.ScanTask;
import entities.ScanTaskArgs;
import ui.panel.subPanel.GlobalConfig;
import ui.panel.subPanel.SqlMapServiceTabPanel;
import ui.panel.subPanel.TaskHistory;

import javax.swing.*;
import java.util.List;

public class ConsoleTab extends JTabbedPane {
    TaskHistory taskHistory;
    GlobalConfig globalConfig;
    SqlMapServiceTabPanel sqlMapServiceTabPanel;

    public ConsoleTab() {
        taskHistory = new TaskHistory();
        globalConfig = new GlobalConfig();
        sqlMapServiceTabPanel = new SqlMapServiceTabPanel();


        add("任务列表", taskHistory);
        add("配置", globalConfig);
        add("后台服务", sqlMapServiceTabPanel);

        setComponentAt(0, taskHistory);
        setComponentAt(1, globalConfig);
        setComponentAt(2, sqlMapServiceTabPanel);
    }

    public void addNewScanTask(ScanTask scanTask) {
        taskHistory.addNewScanTask(scanTask);
    }

    public void addNewScanTask(IHttpRequestResponse httpRequestResponse, String name) {
        taskHistory.addNewScanTask(httpRequestResponse, name);
    }

    public int getNewScanTaskId() {
        return taskHistory.getNewScanTaskId();
    }


    public List<ScanTaskArgs> getScanTaskArgsList() {
        return globalConfig.getScanTaskArgsList();
    }
}
