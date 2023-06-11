package ui.component;

import burp.IHttpRequestResponse;
import entities.TaskItem;
import utils.Autocomplete;
import utils.MyStringUtil;

import javax.swing.*;
import java.awt.*;

import static utils.GlobalStaticVariables.*;

public class ScanTaskConfigLevel1 extends JFrame {
    JPanel taskNamePanel;
    JLabel taskNameLabel;
    JTextField taskNameTextField;

    JPanel commandLinePanel;
    JLabel commandLineLabel;
    JTextField commandLineTextFiled;

    JPanel btnPanel;
    JButton okBtn;
    JButton cancelBtn;

    IHttpRequestResponse httpRequestResponse;

    public ScanTaskConfigLevel1(IHttpRequestResponse httpRequestResponse) throws HeadlessException {
        setTitle(EX_MSG.getMsg("configLevel") + "-" + EX_MSG.getMsg("one"));
        setLayout(new BorderLayout());
        this.httpRequestResponse = httpRequestResponse;

        taskNamePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        taskNameLabel = new JLabel(EX_MSG.getMsg("taskName"));
        taskNameTextField = new JTextField("task-" + MyStringUtil.getDateTimeStr(0), 64);

        taskNamePanel.add(taskNameLabel);
        taskNamePanel.add(taskNameTextField);

        add(taskNamePanel, BorderLayout.NORTH);

        commandLinePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        commandLineLabel = new JLabel(EX_MSG.getMsg("commandLine"));

        commandLineTextFiled = new JTextField("", 64);

        commandLineTextFiled.setFocusTraversalKeysEnabled(false);
        Autocomplete autoComplete = new Autocomplete(commandLineTextFiled, SCAN_OPTIONS_KEYWORDS);
        commandLineTextFiled.getDocument().addDocumentListener(autoComplete);
        commandLineTextFiled.getInputMap().put(KeyStroke.getKeyStroke("TAB"), COMMIT_ACTION);
        commandLineTextFiled.getActionMap().put(COMMIT_ACTION, autoComplete.new CommitAction());

        commandLinePanel.add(commandLineLabel);
        commandLinePanel.add(commandLineTextFiled);

        add(commandLinePanel, BorderLayout.CENTER);

        btnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        okBtn = new JButton(EX_MSG.getMsg("ok"));
        cancelBtn = new JButton(EX_MSG.getMsg("cancel"));

        btnPanel.add(okBtn);
        btnPanel.add(cancelBtn);

        add(btnPanel, BorderLayout.SOUTH);

        initActionListening();

        pack();
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    }

    private void initActionListening() {
        okBtn.addActionListener(e -> {
            String taskName = taskNameTextField.getText();
            if (null == taskName || taskName.trim().isEmpty()) {
                dispose();
                return;
            }

//            String commandLineStr = null;
            String commandLineTextFieldText = commandLineTextFiled.getText();


            if (null == commandLineTextFieldText || commandLineTextFieldText.trim().isEmpty()) {
                dispose();
                return;
            }

            do {
                if (SCAN_TASK_QUEUE_MAX_SIZE > SCAN_TASK_QUEUE.size()) {
                    SCAN_TASK_QUEUE.offer(new TaskItem(taskName, commandLineTextFieldText, httpRequestResponse));
                    break;
                }
            } while (true);

            dispose();
        });


        cancelBtn.addActionListener(e -> dispose());

    }
}
