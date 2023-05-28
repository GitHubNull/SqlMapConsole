package ui.component;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import entities.OptionsCommandLine;
import models.CommandLineTableModel;
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
    CommandLineTableModel commandLineTableModel;


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
        commandLineTableModel = new CommandLineTableModel();
        table.setModel(commandLineTableModel);
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

    public void setScanTaskArgsList(List<OptionsCommandLine> optionsCommandLineList) {
        commandLineTableModel.setScanTaskArgsList(optionsCommandLineList);
    }

    private void initActionBlistering() {
        okBtn.addActionListener(e -> {
            String taskName = taskNameTextField.getText();
            if (null == taskName || taskName.trim().isEmpty()) {
                dispose();
                return;
            }

            int tableSelectIndex = table.getSelectedRow();
            if (0 >= commandLineTableModel.getRowCount() && (0 > tableSelectIndex || commandLineTableModel.getRowCount() <= tableSelectIndex)) {
                return;
            }

            String commandLineStr = commandLineTableModel.getOptionsCommandLineById(tableSelectIndex).getCommandLineStr();
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
