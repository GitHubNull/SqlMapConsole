package ui.component;

import burp.BurpExtender;
import burp.IMessageEditor;
import controller.MessageEditorController;
import entities.ScanTask;
import utils.Autocomplete;
import utils.GlobalStaticsVar;

import javax.swing.*;
import java.awt.*;

public class ScanTaskEditorDialog extends JFrame {
    ScanTask scanTask;

    JPanel commandLinePanel;
    JLabel commandLineLabel;

    JTextField commandLineTextField;


    JSplitPane messageEditorView;

    IMessageEditor requestMessageEditor;

    //    JScrollPane responseViewPanel;
    IMessageEditor responseMessageEditor;

    JPanel buttonPanel;
    JButton okBtn;
    JButton cancelBtn;

    public ScanTaskEditorDialog(ScanTask scanTask) {
        this.scanTask = scanTask;

        setTitle("扫描任务编辑");
        setLayout(new BorderLayout());

        commandLinePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        commandLineLabel = new JLabel("命令行参数");

        commandLineTextField = new JTextField(scanTask.getCmdLine(), 64);
        commandLineTextField.setCaretPosition(scanTask.getCmdLine().length());
        commandLineTextField.setFocusTraversalKeysEnabled(false);
        Autocomplete autoComplete = new Autocomplete(commandLineTextField, GlobalStaticsVar.SCAN_OPTIONS_KEYWORDS);
        commandLineTextField.getDocument().addDocumentListener(autoComplete);
        commandLineTextField.getInputMap().put(KeyStroke.getKeyStroke("TAB"), utils.GlobalStaticsVar.COMMIT_ACTION);
        commandLineTextField.getActionMap().put(utils.GlobalStaticsVar.COMMIT_ACTION, autoComplete.new CommitAction());

        commandLinePanel.add(commandLineLabel);
        commandLinePanel.add(commandLineTextField);

        add(commandLinePanel, BorderLayout.NORTH);

        requestMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), true);
        requestMessageEditor.setMessage(scanTask.getRequestResponse().getRequest(), true);

        responseMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), false);
        responseMessageEditor.setMessage(scanTask.getRequestResponse().getResponse(), false);

        messageEditorView = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestMessageEditor.getComponent(),
                responseMessageEditor.getComponent());

        add(messageEditorView, BorderLayout.CENTER);


        buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        okBtn = new JButton("确定");
        cancelBtn = new JButton("取消");

        buttonPanel.add(okBtn);
        buttonPanel.add(cancelBtn);

        add(buttonPanel, BorderLayout.SOUTH);

        pack();
        setSize(getPreferredSize());
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        initActionListeners();

    }

    private void initActionListeners() {
        okBtn.addActionListener(e -> {
            byte[] requestBytes = requestMessageEditor.getMessage();
            String cmdLineStr = commandLineTextField.getText();

            if (null == requestBytes || 0 == requestBytes.length || null == cmdLineStr || cmdLineStr.trim().isEmpty()) {
                dispose();
                return;
            }

            cmdLineStr = cmdLineStr.trim();
            scanTask.setCmdLine(cmdLineStr);

            scanTask.getRequestResponse().setRequest(requestBytes);

            dispose();
        });

        cancelBtn.addActionListener(e -> dispose());
    }
}
