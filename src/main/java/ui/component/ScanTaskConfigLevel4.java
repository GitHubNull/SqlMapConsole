package ui.component;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import controller.MessageEditorController;
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

public class ScanTaskConfigLevel4 extends JFrame {
    private final IHttpRequestResponse httpRequestResponse;
    JPanel northPanel;

    JTextPane requestViewPanel;
    IMessageEditor requestMessageEditor;


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
    JPanel southArgsContainer;

    JPanel commandLineTagPanel;
    JLabel commandLineTagLabel;
    JTextField commandLineTagTextField;

    JPanel commandLinePanel;
    JLabel commandLineLabel;
    JTextField commandLineTextFiled;
    Autocomplete autoComplete;

    JPanel commandLineOperationPanel;
    JButton addBtn;
    JButton useBtn;
    JButton addAndOkBtn;


//    JPanel southTaskOperationContainer;

    JPanel taskNamePanel;
    JLabel taskNameLabel;
    JTextField taskNameTextField;

    //    JPanel operationPanelContainer;
    JPanel operationPanel;
    JButton okBtn;
    JButton cancelBtn;


    public ScanTaskConfigLevel4(IHttpRequestResponse httpRequestResponse) throws HeadlessException {
        setTitle("配置扫描参数（带标记）");
        setLayout(new BorderLayout());
        this.httpRequestResponse = httpRequestResponse;


        requestMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), true);
        requestMessageEditor.setMessage(httpRequestResponse.getRequest(), true);
//        requestMessageEditor.set

        northPanel = new JPanel(new BorderLayout());

//        requestViewPanel = new JTextPane();
//        requestViewPanel.setBorder(new TitledBorder("请求报文"));
//
//        requestViewPanel.setText("helllo");


        northPanel.add(requestMessageEditor.getComponent(), BorderLayout.CENTER);


//        northPanel.add(operationPanel, BorderLayout.SOUTH);

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

        tableContainerPanel = new JScrollPane(table, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        centerPanel.add(tableContainerPanel, BorderLayout.CENTER);


        add(centerPanel, BorderLayout.CENTER);


        southPanel = new JPanel(new BorderLayout());

        southArgsContainer = new JPanel(new BorderLayout());

        commandLineTagPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        commandLineTagLabel = new JLabel("标签");

        commandLineTagTextField = new JTextField(MyStringUtil.getDateTimeStr(0));
        commandLineTagTextField.setColumns(64);


        commandLineTagPanel.add(commandLineTagLabel);
        commandLineTagPanel.add(commandLineTagTextField);

        commandLinePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        commandLineLabel = new JLabel("参数");

        commandLineTextFiled = new JTextField(64);
        commandLineTextFiled.setFocusTraversalKeysEnabled(false);
        autoComplete = new Autocomplete(commandLineTextFiled, SCAN_OPTIONS_KEYWORDS);
        commandLineTextFiled.getDocument().addDocumentListener(autoComplete);
        commandLineTextFiled.getInputMap().put(KeyStroke.getKeyStroke("TAB"), COMMIT_ACTION);
        commandLineTextFiled.getActionMap().put(COMMIT_ACTION, autoComplete.new CommitAction());

        commandLinePanel.add(commandLineLabel);
        commandLinePanel.add(commandLineTextFiled);

        commandLineOperationPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton("添加");
        useBtn = new JButton("使用");
        addAndOkBtn = new JButton("添加并使用");
        commandLineOperationPanel.add(addBtn);
        commandLineOperationPanel.add(useBtn);
        commandLineOperationPanel.add(addAndOkBtn);

        southArgsContainer.add(commandLineTagPanel, BorderLayout.NORTH);
        southArgsContainer.add(commandLinePanel, BorderLayout.CENTER);
        southArgsContainer.add(commandLineOperationPanel, BorderLayout.SOUTH);

        southPanel.add(southArgsContainer, BorderLayout.NORTH);

        taskNamePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        taskNameLabel = new JLabel("任务名");

        taskNameTextField = new JTextField("task-" + MyStringUtil.getDateTimeStr(0));
        taskNameTextField.setColumns(64);

        taskNamePanel.add(taskNameLabel);
        taskNamePanel.add(taskNameTextField);

        southPanel.add(taskNamePanel, BorderLayout.CENTER);

        operationPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        okBtn = new JButton("确定");
        cancelBtn = new JButton("取消");
        operationPanel.add(okBtn);
        operationPanel.add(cancelBtn);

        southPanel.add(operationPanel, BorderLayout.SOUTH);

        add(southPanel, BorderLayout.SOUTH);


        initActionListener();


        pack();
        setMinimumSize(getPreferredSize());
        setSize(getMinimumSize());
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);
//        setVisible(true);

    }

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

            byte[] httpBytesData = requestMessageEditor.getMessage();
            httpRequestResponse.setRequest(httpBytesData);


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
