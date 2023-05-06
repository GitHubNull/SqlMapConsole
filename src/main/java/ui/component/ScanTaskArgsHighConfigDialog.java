package ui.component;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import controller.MessageEditorController;
import entities.ScanTaskArgs;
import entities.ScanTaskArgsColumnName;
import models.ScanTaskArgsTableModel;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class ScanTaskArgsHighConfigDialog extends JFrame {
    JPanel northPanel;

    JTextPane requestViewPanel;
    IMessageEditor requestMessageEditor;

    JPanel operationPanel;
    JButton okBtn;
    JButton cancelBtn;


    JPanel centerPanel;
    JPanel filterPane;
    JComboBox<String> filterColumnSelectionComboBox;
    JLabel filterLabel;
    JTextField filterTextField;
    JButton filterBtn;

    JScrollPane tableContainerPanel;

    JTable table;
    ScanTaskArgsTableModel scanTaskArgsTableModel;


    JPanel southPanel;
    JPanel tagPanel;
    JLabel tagLabel;
    JTextField tagTextField;

    JPanel argsPanel;
    JLabel argsLabel;
    JTextField argsTextFiled;

    JPanel argsOperationPanel;
    JButton addBtn;
    JButton addAndOkBtn;


    public ScanTaskArgsHighConfigDialog(IHttpRequestResponse httpRequestResponse) throws HeadlessException {
        setTitle("配置扫描参数（带标记）");
        setLayout(new BorderLayout());


        requestMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), true);
        requestMessageEditor.setMessage(httpRequestResponse.getRequest(), true);
//        requestMessageEditor.set

        northPanel = new JPanel(new BorderLayout());

//        requestViewPanel = new JTextPane();
//        requestViewPanel.setBorder(new TitledBorder("请求报文"));
//
//        requestViewPanel.setText("helllo");


        northPanel.add(requestMessageEditor.getComponent(), BorderLayout.CENTER);

        operationPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        okBtn = new JButton("确定");
        cancelBtn = new JButton("取消");
        operationPanel.add(okBtn);
        operationPanel.add(cancelBtn);

        northPanel.add(operationPanel, BorderLayout.SOUTH);

        add(northPanel, BorderLayout.NORTH);


        centerPanel = new JPanel(new BorderLayout());

        filterPane = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filterColumnSelectionComboBox = new JComboBox<>(new String[]{ScanTaskArgsColumnName.TAG.toString(), ScanTaskArgsColumnName.ARGS_STR.toString()});
        filterLabel = new JLabel("按照");
        filterTextField = new JTextField(16);
        filterBtn = new JButton("过滤");

        filterPane.add(filterLabel);
        filterPane.add(filterColumnSelectionComboBox);
        filterPane.add(filterTextField);
        filterPane.add(filterBtn);

        centerPanel.add(filterPane, BorderLayout.NORTH);

        table = new JTable();

        scanTaskArgsTableModel = new ScanTaskArgsTableModel();

        table.setModel(scanTaskArgsTableModel);

        tableContainerPanel = new JScrollPane(table, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        centerPanel.add(tableContainerPanel, BorderLayout.CENTER);


        add(centerPanel, BorderLayout.CENTER);


        southPanel = new JPanel(new BorderLayout());

        tagPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        tagLabel = new JLabel("标签");
        tagTextField = new JTextField(16);
        tagPanel.add(tagLabel);
        tagPanel.add(tagTextField);

        argsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        argsLabel = new JLabel("参数");
        argsTextFiled = new JTextField(64);
        argsPanel.add(argsLabel);
        argsPanel.add(argsTextFiled);

        argsOperationPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton("添加");
        addAndOkBtn = new JButton("添加并使用");
        argsOperationPanel.add(addBtn);
        argsOperationPanel.add(addAndOkBtn);

        southPanel.add(tagPanel, BorderLayout.NORTH);
        southPanel.add(argsPanel, BorderLayout.CENTER);
        southPanel.add(argsOperationPanel, BorderLayout.SOUTH);


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
        okBtn.addActionListener(e -> dispose());

        cancelBtn.addActionListener(e -> {
            dispose();
//                setVisible(false);
        });


    }

    public void setScanTaskArgsList(List<ScanTaskArgs> scanTaskArgsList) {
        scanTaskArgsTableModel.setScanTaskArgsList(scanTaskArgsList);
    }
}
