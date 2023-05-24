package ui.component;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import entities.ScanTaskArgsColumnName;
import entities.ScanTaskOptionsCommandLine;
import models.ScanTaskCommandLineTableModel;
import utils.Autocomplete;
import utils.MyStringUtil;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.util.List;

import static utils.GlobalStaticsVar.COMMIT_ACTION;
import static utils.GlobalStaticsVar.SCAN_OPTIONS_KEYWORDS;

public class ScanTaskConfigLevel3 extends JFrame {
    private final IHttpRequestResponse httpRequestResponse;
    JPanel northPanel;
    JPanel commandLineTagPanel;
    JLabel commandLineTagLabel;
    JTextField commandLineTagTextField;

    JPanel commandLinePanel;
    JLabel commandLineLabel;
    JTextField commandLineTextFiled;


    JPanel btnPanel;
    JButton useBtn;
    JButton addBtn;
    JButton addAndOkBtn;

    JPanel centerPanel;

    JPanel filterPane;
    JComboBox<String> filterColumnSelectionComboBox;
    JLabel filterLabel;
    JTextField filterTextField;
    JButton filterBtn;

    JScrollPane tableContainerPanel;
    JTable table;
    ScanTaskCommandLineTableModel scanTaskCommandLineTableModel;

    JPanel southPanel;

    JPanel southTaskNamePanel;
    JLabel taskNameLabel;
    JTextField taskNameTextField;


    JPanel southBtnPanel;
    JButton okBtn;
    JButton cancelBtn;

    public ScanTaskConfigLevel3(IHttpRequestResponse httpRequestResponse) throws HeadlessException {
        setTitle("扫描参数配置");
        setLayout(new BorderLayout());
        this.httpRequestResponse = httpRequestResponse;


        northPanel = new JPanel(new BorderLayout());

        commandLineTagPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        commandLineTagLabel = new JLabel("标签");
        commandLineTagTextField = new JTextField(MyStringUtil.getDateTimeStr(0));
        commandLineTagTextField.setColumns(64);
//        tagTextField.setCol
//        tagTextField.setMinimumSize(new Dimension(10, 12));
        commandLineTagPanel.add(commandLineTagLabel);
        commandLineTagPanel.add(commandLineTagTextField);

        commandLinePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        commandLineLabel = new JLabel("参数");

        commandLineTextFiled = new JTextField(64);
        commandLineTextFiled.setFocusTraversalKeysEnabled(false);
        Autocomplete autoComplete = new Autocomplete(commandLineTextFiled, SCAN_OPTIONS_KEYWORDS);
        commandLineTextFiled.getDocument().addDocumentListener(autoComplete);
        commandLineTextFiled.getInputMap().put(KeyStroke.getKeyStroke("TAB"), COMMIT_ACTION);
        commandLineTextFiled.getActionMap().put(COMMIT_ACTION, autoComplete.new CommitAction());

        commandLinePanel.add(commandLineLabel);
        commandLinePanel.add(commandLineTextFiled);


        btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton("新增");
        useBtn = new JButton("使用");
        addAndOkBtn = new JButton("新增并使用");
        btnPanel.add(addBtn);
        btnPanel.add(useBtn);
        btnPanel.add(addAndOkBtn);

        northPanel.add(commandLineTagPanel, BorderLayout.NORTH);
        northPanel.add(commandLinePanel, BorderLayout.CENTER);
        northPanel.add(btnPanel, BorderLayout.SOUTH);

        add(northPanel, BorderLayout.NORTH);


        centerPanel = new JPanel(new BorderLayout());


        filterPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filterColumnSelectionComboBox = new JComboBox<>(new String[]{ScanTaskArgsColumnName.TAG.toString(), ScanTaskArgsColumnName.ARGS_STR.toString()});
        filterLabel = new JLabel("按照");
        filterTextField = new JTextField(64);
        filterBtn = new JButton("过滤");

        filterPane.add(filterLabel);
        filterPane.add(filterColumnSelectionComboBox);
        filterPane.add(filterTextField);
        filterPane.add(filterBtn);

        centerPanel.add(filterPane, BorderLayout.NORTH);


        table = new JTable();
        scanTaskCommandLineTableModel = new ScanTaskCommandLineTableModel();
        table.setModel(scanTaskCommandLineTableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        tableContainerPanel = new JScrollPane(table);
        centerPanel.add(tableContainerPanel, BorderLayout.CENTER);


        add(centerPanel, BorderLayout.CENTER);


        southPanel = new JPanel(new BorderLayout());

        southTaskNamePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        taskNameLabel = new JLabel("任务名");
        taskNameTextField = new JTextField("task-" + MyStringUtil.getDateTimeStr(0));
        taskNameTextField.setColumns(64);

        southTaskNamePanel.add(taskNameLabel);
        southTaskNamePanel.add(taskNameTextField);

        southPanel.add(southTaskNamePanel, BorderLayout.CENTER);


        southBtnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));


        okBtn = new JButton("确定");
        cancelBtn = new JButton("取消");

        southBtnPanel.add(okBtn);
        southBtnPanel.add(cancelBtn);

        southPanel.add(southBtnPanel, BorderLayout.SOUTH);

        add(southPanel, BorderLayout.SOUTH);


        initActionListener();


        setMinimumSize(getPreferredSize());
        setSize(getMinimumSize());
        pack();
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);
//        setVisible(true);
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

    public void initActionListener() {
        okBtn.addActionListener(e -> {
            String taskName = taskNameTextField.getText();
            if (null == taskName || taskName.trim().isEmpty()) {
                dispose();
                return;
            }

            String commandLineStr = null;
            String commandLineTextFieldText = commandLineTextFiled.getText();

            int tableSelectIndex = table.getSelectedRow();
            String tableCommandLineStr = null;
            if (0 < scanTaskCommandLineTableModel.getRowCount() && (0 <= tableSelectIndex ||
                    scanTaskCommandLineTableModel.getRowCount() > tableSelectIndex)) {
                ScanTaskOptionsCommandLine scanTaskOptionsCommandLine =
                        scanTaskCommandLineTableModel.getScanTaskOptionsCommandLineById(tableSelectIndex);
                if (null != scanTaskOptionsCommandLine) {
                    tableCommandLineStr = scanTaskOptionsCommandLine.getCommandLineStr();
                }

            }

            if ((null == commandLineTextFieldText || commandLineTextFieldText.trim().isEmpty()) && (null == tableCommandLineStr || tableCommandLineStr.trim().isEmpty())) {
                dispose();
                return;
            }

            if (null == commandLineTextFieldText || commandLineTextFieldText.trim().isEmpty()) {
                commandLineStr = tableCommandLineStr;
            } else {
                commandLineStr = commandLineTextFieldText;
            }

            try {
                BurpExtender.startScanTask(taskName, commandLineStr, httpRequestResponse);
            } catch (IOException ex) {
                BurpExtender.stderr.println(ex.getMessage());
//                throw new RuntimeException(ex);
            }

            dispose();
        });

        cancelBtn.addActionListener(e -> {
            dispose();
//                setVisible(false);
        });

        useBtn.addActionListener(e -> {

            dispose();
        });


    }

    public void setScanTaskArgsList(List<ScanTaskOptionsCommandLine> scanTaskOptionsCommandLineList) {
        scanTaskCommandLineTableModel.setScanTaskArgsList(scanTaskOptionsCommandLineList);
    }
}
