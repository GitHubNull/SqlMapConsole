package ui.component;

import entities.ScanTaskArgs;
import models.ScanTaskArgsTableModel;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class ScanTaskArgsLowConfigDialog extends JFrame {
    JScrollPane tableContainer;
    JTable table;
    ScanTaskArgsTableModel scanTaskArgsTableModel;


    JPanel south;
    JButton okBtn;
    JButton cancelBtn;

    public ScanTaskArgsLowConfigDialog() throws HeadlessException {
        setTitle("简单配置");
        setLayout(new BorderLayout());


        table = new JTable();
        scanTaskArgsTableModel = new ScanTaskArgsTableModel();
        table.setModel(scanTaskArgsTableModel);


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

    public void setScanTaskArgsList(List<ScanTaskArgs> scanTaskArgsList) {
        scanTaskArgsTableModel.setScanTaskArgsList(scanTaskArgsList);
    }

    private void initActionBlistering() {
        okBtn.addActionListener(e -> {
            // TODO other code

            dispose();
        });

        cancelBtn.addActionListener(e -> dispose());


    }
}
