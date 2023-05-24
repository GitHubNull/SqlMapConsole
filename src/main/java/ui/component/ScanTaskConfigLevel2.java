package ui.component;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import entities.ScanTaskOptionsCommandLine;
import models.ScanTaskCommandLineTableModel;
import utils.MyStringUtil;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.util.List;

public class ScanTaskConfigLevel2 extends JFrame {
    JPanel north;
    JLabel taskNameLabel;
    JTextField taskNameTextField;

    JScrollPane tableContainer;
    JTable table;
    ScanTaskCommandLineTableModel scanTaskCommandLineTableModel;


    JPanel south;
    JButton okBtn;
    JButton cancelBtn;

    IHttpRequestResponse httpRequestResponse;

    public ScanTaskConfigLevel2(IHttpRequestResponse httpRequestResponse) throws HeadlessException {
        setTitle("简单配置");
        setLayout(new BorderLayout());
        this.httpRequestResponse = httpRequestResponse;


        north = new JPanel(new FlowLayout(FlowLayout.LEFT));
        taskNameLabel = new JLabel("任务名");
        taskNameTextField = new JTextField("task-" + MyStringUtil.getDateTimeStr(0));
        taskNameTextField.setColumns(64);

        north.add(taskNameLabel);
        north.add(taskNameTextField);

        add(north, BorderLayout.NORTH);


        table = new JTable();
        scanTaskCommandLineTableModel = new ScanTaskCommandLineTableModel();
        table.setModel(scanTaskCommandLineTableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);


        tableContainer = new JScrollPane(table);

        add(tableContainer, BorderLayout.CENTER);


        south = new JPanel(new FlowLayout(FlowLayout.CENTER));

        okBtn = new JButton("确定");
        cancelBtn = new JButton("取消");

        south.add(okBtn);
        south.add(cancelBtn);


        add(south, BorderLayout.SOUTH);

        initActionBlistering();
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);


        setMinimumSize(getPreferredSize());
        setSize(getMinimumSize());
        pack();
        setLocationRelativeTo(null);
//        setVisible(true);

    }

    public void setScanTaskArgsList(List<ScanTaskOptionsCommandLine> scanTaskOptionsCommandLineList) {
        scanTaskCommandLineTableModel.setScanTaskArgsList(scanTaskOptionsCommandLineList);
    }

//    private void startScanTask(String taskName, String commandLineStr){
//        final String finalCommandLineStr = commandLineStr;
//
//        SwingUtilities.invokeLater(() -> {
//
//            SqlMapApiClient sqlMapApiClient = BurpExtender.getSqlMapApiClient();
//
//            Call call = sqlMapApiClient.genScanTaskId();
//            if (null == call) {
//                return;
//            }
//
//            call.enqueue(new Callback() {
//                @Override
//                public void onFailure(@NotNull Call call, @NotNull IOException e) {
//                    BurpExtender.stderr.println(e.getMessage());
//                }
//
//                @Override
//                public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
//                    assert response.body() != null;
//                    sqlmapApi.responsesBody.TaskNewResponse taskNewResponse = JSON.parseObject(response.body().string(), TaskNewResponse.class);
//                    if (!taskNewResponse.getSuccess()) {
//                        return;
//                    }
//
//
//                    ScanOptions scanOptions = null;
//                    try {
//                        scanOptions = ScanOptionsHelper.CommandLine2ScanOptions(finalCommandLineStr);
//                    } catch (IllegalAccessException ex) {
//                        BurpExtender.stderr.println(ex.getMessage());
//                        return;
////                            throw new RuntimeException(ex);
//                    }
////                        ScanOptions scanOptions = new ScanOptions();
//
//
//                    // push task to sqlmapApi
//                    if (null == scanOptions.getRequestFile() || scanOptions.getRequestFile().isEmpty()){
//                        final String tmpRequestFilePath = TmpRequestFileHelper.writeBytesToFile(httpRequestResponse.getRequest());
//                        if (null == tmpRequestFilePath){
//                            sqlMapApiClient.deleteScanTask(taskNewResponse.getTaskid());
//                            return;
//                        }
//
//                        scanOptions.setRequestFile(tmpRequestFilePath);
//                    }
//
//                    Call callIn = sqlMapApiClient.addScanTask(taskNewResponse.getTaskid(), scanOptions);
//                    if (null == callIn) {
//                        return;
//                    }
//
//                    callIn.enqueue(new Callback() {
//                        @Override
//                        public void onFailure(@NotNull Call call, @NotNull IOException e) {
//                            BurpExtender.stderr.println(e.getMessage());
//                        }
//
//                        @Override
//                        public void onResponse(@NotNull Call call, @NotNull Response response) {
//
//                            // add new row to history panel
//                            BurpExtender.addScanTaskToTaskHistory(httpRequestResponse, taskName, taskNewResponse.getTaskid());
//
//                            ScanTaskTableModel scanTaskTableModel = BurpExtender.getScanTaskTableModel();
//                            int index = scanTaskTableModel.getScanTaskIndexByTaskId(taskNewResponse.getTaskid());
//                            if (-1 == index) {
//                                return;
//                            }
//
//                            // push scan status item to scan_status_queue
//                            SwingUtilities.invokeLater(() -> GlobalStaticsVar.TASK_ID_INDEX_MAP_QUEUE.offer(new TaskId2TaskIndexMap(taskNewResponse.getTaskid(), index)));
//
//                        }
//                    });
//
//                }
//            });
//
//
//        });
//    }

    private void initActionBlistering() {
        okBtn.addActionListener(e -> {
            String taskName = taskNameTextField.getText();
            if (null == taskName || taskName.trim().isEmpty()) {
                dispose();
                return;
            }

            int tableSelectIndex = table.getSelectedRow();
            if (0 >= scanTaskCommandLineTableModel.getRowCount() && (0 > tableSelectIndex || scanTaskCommandLineTableModel.getRowCount() <= tableSelectIndex)) {
                return;
            }

            String commandLineStr = scanTaskCommandLineTableModel.getScanTaskOptionsCommandLineById(tableSelectIndex).getCommandLineStr();
            if (null == commandLineStr || commandLineStr.trim().isEmpty()) {
                return;
            }

            commandLineStr = commandLineStr.trim();


            try {
                BurpExtender.startScanTask(taskName, commandLineStr, httpRequestResponse);
            } catch (IOException ex) {
                BurpExtender.stderr.println(ex.getMessage());
//                throw new RuntimeException(ex);
            }

//            startScanTask(taskName, commandLineStr);

            dispose();
        });

        cancelBtn.addActionListener(e -> dispose());

    }
}
