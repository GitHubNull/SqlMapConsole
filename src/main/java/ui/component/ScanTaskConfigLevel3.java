package ui.component;

import burp.IHttpRequestResponse;
import entities.CommandLineColumnName;
import entities.OptionsCommandLine;
import entities.TaskItem;
import models.CommandLineTableModel;
import utils.Autocomplete;
import utils.MyStringUtil;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import static utils.GlobalStaticVariables.*;

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
    JButton refBtn;
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
    CommandLineTableModel commandLineTableModel;

    JPanel southPanel;

    JPanel southTaskNamePanel;
    JLabel taskNameLabel;
    JTextField taskNameTextField;


    JPanel southBtnPanel;
    JButton okBtn;
    JButton cancelBtn;

    public ScanTaskConfigLevel3(IHttpRequestResponse httpRequestResponse) throws HeadlessException {
        setTitle(EX_MSG.getMsg("configLevel") + "-" + EX_MSG.getMsg("three"));
        setLayout(new BorderLayout());
        this.httpRequestResponse = httpRequestResponse;


        northPanel = new JPanel(new BorderLayout());

        commandLineTagPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        commandLineTagLabel = new JLabel("标签");
        commandLineTagTextField = new JTextField(MyStringUtil.getDateTimeStr(0));
        commandLineTagTextField.setColumns(64);

        commandLineTagPanel.add(commandLineTagLabel);
        commandLineTagPanel.add(commandLineTagTextField);

        commandLinePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        commandLineLabel = new JLabel(EX_MSG.getMsg("commandLine"));

        commandLineTextFiled = new JTextField(64);
        commandLineTextFiled.setFocusTraversalKeysEnabled(false);
        Autocomplete autoComplete = new Autocomplete(commandLineTextFiled, SCAN_OPTIONS_KEYWORDS);
        commandLineTextFiled.getDocument().addDocumentListener(autoComplete);
        commandLineTextFiled.getInputMap().put(KeyStroke.getKeyStroke("TAB"), COMMIT_ACTION);
        commandLineTextFiled.getActionMap().put(COMMIT_ACTION, autoComplete.new CommitAction());

        commandLinePanel.add(commandLineLabel);
        commandLinePanel.add(commandLineTextFiled);


        btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton(EX_MSG.getMsg("add"));
        useBtn = new JButton(EX_MSG.getMsg("useIt"));
        refBtn = new JButton(EX_MSG.getMsg("reference"));
        addAndOkBtn = new JButton(EX_MSG.getMsg("addAndUseIt"));
        btnPanel.add(addBtn);
        btnPanel.add(useBtn);
        btnPanel.add(refBtn);
        btnPanel.add(addAndOkBtn);

        northPanel.add(commandLineTagPanel, BorderLayout.NORTH);
        northPanel.add(commandLinePanel, BorderLayout.CENTER);
        northPanel.add(btnPanel, BorderLayout.SOUTH);

        add(northPanel, BorderLayout.NORTH);


        centerPanel = new JPanel(new BorderLayout());


        filterPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filterColumnSelectionComboBox = new JComboBox<>(new String[]{CommandLineColumnName.TAG, CommandLineColumnName.COMMAND_LINE});
        filterLabel = new JLabel(EX_MSG.getMsg("by"));
        filterTextField = new JTextField(64);
        filterBtn = new JButton(EX_MSG.getMsg("filter"));

        filterPane.add(filterLabel);
        filterPane.add(filterColumnSelectionComboBox);
        filterPane.add(filterTextField);
        filterPane.add(filterBtn);

        centerPanel.add(filterPane, BorderLayout.NORTH);


        table = new JTable();
        commandLineTableModel = new CommandLineTableModel();
        table.setModel(commandLineTableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        tableContainerPanel = new JScrollPane(table);
        centerPanel.add(tableContainerPanel, BorderLayout.CENTER);


        add(centerPanel, BorderLayout.CENTER);


        southPanel = new JPanel(new BorderLayout());

        southTaskNamePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        taskNameLabel = new JLabel(EX_MSG.getMsg("taskName"));
        taskNameTextField = new JTextField("task-" + MyStringUtil.getDateTimeStr(0));
        taskNameTextField.setColumns(64);

        southTaskNamePanel.add(taskNameLabel);
        southTaskNamePanel.add(taskNameTextField);

        southPanel.add(southTaskNamePanel, BorderLayout.CENTER);


        southBtnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));


        okBtn = new JButton(EX_MSG.getMsg("ok"));
        cancelBtn = new JButton(EX_MSG.getMsg("cancel"));

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
    }

    public void initActionListener() {
        okBtn.addActionListener(e -> {
            String taskName = taskNameTextField.getText();
            if (null == taskName || taskName.trim().isEmpty()) {
                dispose();
                return;
            }

            String commandLineStr;
            String commandLineTextFieldText = commandLineTextFiled.getText();

            int tableSelectIndex = table.getSelectedRow();
            String tableCommandLineStr = null;
            if (0 < commandLineTableModel.getRowCount() && (0 <= tableSelectIndex ||
                    commandLineTableModel.getRowCount() > tableSelectIndex)) {
                OptionsCommandLine optionsCommandLine =
                        commandLineTableModel.getOptionsCommandLineById(tableSelectIndex);
                if (null != optionsCommandLine) {
                    tableCommandLineStr = optionsCommandLine.getCommandLineStr();
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

            do {
                if (SCAN_TASK_QUEUE_MAX_SIZE > SCAN_TASK_QUEUE.size()) {
                    SCAN_TASK_QUEUE.offer(new TaskItem(taskName, commandLineStr, httpRequestResponse));
                    break;
                }
            } while (true);

//            try {
//                BurpExtender.startScanTask(taskName, commandLineStr, httpRequestResponse);
//            } catch (IOException ex) {
//                BurpExtender.stderr.println(ex.getMessage());
//            }

            dispose();
        });

        cancelBtn.addActionListener(e -> dispose());

        useBtn.addActionListener(e -> {
            String taskName = taskNameTextField.getText();
            if (null == taskName || taskName.trim().isEmpty()) {
                dispose();
                return;
            }

            String commandLineTextFieldText = commandLineTextFiled.getText();
            if ((null == commandLineTextFieldText || commandLineTextFieldText.trim().isEmpty())) {
                dispose();
                return;
            }

            commandLineTextFieldText = commandLineTextFieldText.trim();

            do {
                if (SCAN_TASK_QUEUE_MAX_SIZE > SCAN_TASK_QUEUE.size()) {
                    SCAN_TASK_QUEUE.offer(new TaskItem(taskName, commandLineTextFieldText, httpRequestResponse));
                    break;
                }
            } while (true);

//            try {
//                BurpExtender.startScanTask(taskName, commandLineTextFieldText, httpRequestResponse);
//            } catch (IOException ex) {
//                BurpExtender.stderr.println(ex.getMessage());
//            }

            dispose();
        });

        refBtn.addActionListener(e -> {
            if (0 == commandLineTableModel.getRowCount()) {
                return;
            }

            int[] selectedRows = table.getSelectedRows();
            if (null == selectedRows || 1 != selectedRows.length) {
                return;
            }

            OptionsCommandLine optionsCommandLine = commandLineTableModel.getOptionsCommandLineById(selectedRows[0]);
            if (null == optionsCommandLine) {
                return;
            }

            String cmdLineStr = optionsCommandLine.getCommandLineStr();
            if (null == cmdLineStr || cmdLineStr.trim().isEmpty()) {
                return;
            }

            commandLineTextFiled.setText(cmdLineStr);
            commandLineTextFiled.setCaretPosition(cmdLineStr.length());

        });


    }

    public void setScanTaskArgsList(List<OptionsCommandLine> optionsCommandLineList) {
        List<OptionsCommandLine> refOptionsCommandLineList = new ArrayList<>();
        for (OptionsCommandLine optionsCommandLine : optionsCommandLineList) {
            OptionsCommandLine refOptionsCommandLine = new OptionsCommandLine(optionsCommandLine.getId(),
                    optionsCommandLine.getTag(), optionsCommandLine.getCommandLineStr(), false);

            refOptionsCommandLineList.add(refOptionsCommandLine);
        }
        commandLineTableModel.setScanTaskArgsList(refOptionsCommandLineList);
    }
}
