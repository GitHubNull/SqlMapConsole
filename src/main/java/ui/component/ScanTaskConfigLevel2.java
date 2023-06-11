package ui.component;

import burp.IHttpRequestResponse;
import entities.OptionsCommandLine;
import entities.TaskItem;
import models.CommandLineTableModel;
import utils.MyStringUtil;

import javax.swing.*;
import java.awt.*;
import java.util.List;

import static utils.GlobalStaticVariables.*;

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
        setTitle(EX_MSG.getMsg("configLevel") + "-" + EX_MSG.getMsg("two"));
        setLayout(new BorderLayout());
        this.httpRequestResponse = httpRequestResponse;


        north = new JPanel(new FlowLayout(FlowLayout.LEFT));
        taskNameLabel = new JLabel(EX_MSG.getMsg("taskName"));
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

        okBtn = new JButton(EX_MSG.getMsg("ok"));
        cancelBtn = new JButton(EX_MSG.getMsg("cancel"));

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

//            startScanTask(taskName, commandLineStr);

            dispose();
        });

        cancelBtn.addActionListener(e -> dispose());

    }
}
