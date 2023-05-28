package ui.component;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import utils.Autocomplete;
import utils.MyStringUtil;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;

import static utils.GlobalStaticsVar.COMMIT_ACTION;
import static utils.GlobalStaticsVar.SCAN_OPTIONS_KEYWORDS;

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
        setTitle("config level 1");
        setLayout(new BorderLayout());
        this.httpRequestResponse = httpRequestResponse;

        taskNamePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        taskNameLabel = new JLabel("任务名");
        taskNameTextField = new JTextField("task-" + MyStringUtil.getDateTimeStr(0), 64);

        taskNamePanel.add(taskNameLabel);
        taskNamePanel.add(taskNameTextField);

        add(taskNamePanel, BorderLayout.NORTH);

        commandLinePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        commandLineLabel = new JLabel("参数");

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

        okBtn = new JButton("确定");
        cancelBtn = new JButton("取消");

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

            try {
                BurpExtender.startScanTask(taskName, commandLineTextFieldText, httpRequestResponse);
            } catch (IOException ex) {
                BurpExtender.stderr.println(ex.getMessage());
//                throw new RuntimeException(ex);
            }

            dispose();
        });


        cancelBtn.addActionListener(e -> dispose());

    }
}
