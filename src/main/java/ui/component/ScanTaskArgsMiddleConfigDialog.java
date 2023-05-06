package ui.component;

import entities.ScanTaskArgs;
import entities.ScanTaskArgsColumnName;
import models.ScanTaskArgsTableModel;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class ScanTaskArgsMiddleConfigDialog extends JFrame {
    JPanel northPanel;
    JPanel tagPanel;
    JLabel tagLabel;
    JTextField tagTextField;

    JPanel argsPanel;
    JLabel argsLabel;
    JTextField argsTextFiled;

    JPanel btnPanel;
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
    ScanTaskArgsTableModel scanTaskArgsTableModel;

    JPanel southPanel;
    JButton okBtn;
    JButton cancelBtn;

    public ScanTaskArgsMiddleConfigDialog() throws HeadlessException {
        setTitle("扫描参数配置");
        setLayout(new BorderLayout());


        northPanel = new JPanel(new BorderLayout());

        tagPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        tagLabel = new JLabel("标签");
        tagTextField = new JTextField(16);
//        tagTextField.setCol
//        tagTextField.setMinimumSize(new Dimension(10, 12));
        tagPanel.add(tagLabel);
        tagPanel.add(tagTextField);

        argsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        argsLabel = new JLabel("参数");
        argsTextFiled = new JTextField(64);
        argsPanel.add(argsLabel);
        argsPanel.add(argsTextFiled);


        btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton("新增");
        addAndOkBtn = new JButton("新增并使用");
        btnPanel.add(addBtn);
        btnPanel.add(addAndOkBtn);

        northPanel.add(tagPanel, BorderLayout.NORTH);
        northPanel.add(argsPanel, BorderLayout.CENTER);
        northPanel.add(btnPanel, BorderLayout.SOUTH);

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

        tableContainerPanel = new JScrollPane(table);
        centerPanel.add(tableContainerPanel, BorderLayout.CENTER);


        add(centerPanel, BorderLayout.CENTER);


        southPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        okBtn = new JButton("确定");
        cancelBtn = new JButton("取消");

        southPanel.add(okBtn);
        southPanel.add(cancelBtn);

        add(southPanel, BorderLayout.SOUTH);


        initActionListener();


        setMinimumSize(getPreferredSize());
        setSize(getMinimumSize());
        pack();
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
