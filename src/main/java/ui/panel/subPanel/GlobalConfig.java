package ui.panel.subPanel;

import entities.ScanTaskArgs;
import models.ScanTaskArgsTableModel;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

public class GlobalConfig extends JPanel {
    JPanel northPanel;

    JPanel tagContainerPanel;
    JLabel tagLabel;
    JTextField tagTextField;


    JPanel argsContainerPanel;
    JLabel argsLabel;
    JTextField argsTextField;

    JPanel preOperationContainerPanel;
    JButton addBtn;
    JButton resetBtn;

    JScrollPane centerPanel;
    JTable table;
    ScanTaskArgsTableModel tableModel;


    JPanel southPanel;
    JButton deleteBtn;
    JButton updateBtn;
    JButton selectAllBtn;
    JButton selectNoneBtn;


    public GlobalConfig() {
        setLayout(new BorderLayout());


        northPanel = new JPanel(new BorderLayout());

        tagContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        tagLabel = new JLabel("标签");
        tagTextField = new JTextField(32);
        tagContainerPanel.add(tagLabel);
        tagContainerPanel.add(tagTextField);

        northPanel.add(tagContainerPanel, BorderLayout.NORTH);

        argsContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        argsLabel = new JLabel("参数");
        argsTextField = new JTextField(64);
        argsContainerPanel.add(argsLabel);
        argsContainerPanel.add(argsTextField);

        northPanel.add(argsContainerPanel, BorderLayout.CENTER);

        preOperationContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton("新增");
        resetBtn = new JButton("重置");
        preOperationContainerPanel.add(addBtn);
        preOperationContainerPanel.add(resetBtn);

        northPanel.add(preOperationContainerPanel, BorderLayout.SOUTH);

        add(northPanel, BorderLayout.NORTH);


        table = new JTable();
        tableModel = new ScanTaskArgsTableModel();
        table.setModel(tableModel);

        centerPanel = new JScrollPane(table);

        add(centerPanel, BorderLayout.CENTER);


        southPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        deleteBtn = new JButton("删除");
        updateBtn = new JButton("更新");
        selectAllBtn = new JButton("全选");
        selectNoneBtn = new JButton("全不选");

        southPanel.add(deleteBtn);
        southPanel.add(updateBtn);
        southPanel.add(selectAllBtn);
        southPanel.add(selectNoneBtn);

        add(southPanel, BorderLayout.SOUTH);

        initActionListening();

    }

    private void initNorthBtnActionListening() {
        addBtn.addActionListener(e -> {
            String tagStr = tagTextField.getText();
            String argsStr = argsTextField.getText();

            if (null == tagStr || null == argsStr || tagStr.trim().isEmpty() || argsStr.trim().isEmpty()) {
                return;
            }
            // 校验tag是否重复,重复则不添加
            if (tableModel.isTagExist(tagStr)) {
                return;
            }

            // todo 校验参数合法性

            tableModel.addScanTaskArgs(tagStr, argsStr);
        });

        resetBtn.addActionListener(e -> {
            tagTextField.setText("");
            argsTextField.setText("");
        });
    }

    private void initCenterBtnActionListening() {
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                super.mouseClicked(e);

                int col = table.getSelectedColumn();

                if (0 == tableModel.getRowCount() || 0 != col) {
                    return;
                }

                // todo 弹出参数详情
            }
        });
    }

    private void initSouthBtnActionListening() {
        deleteBtn.addActionListener(e -> {

            if (0 == tableModel.getRowCount()) {
                return;
            }

            int[] selectRows = table.getSelectedRows();
            if (null == selectRows || 0 == selectRows.length) {
                return;
            }

            for (int selectRow : selectRows) {
                tableModel.deleteScanTaskArgsById(selectRow);
            }
        });

        updateBtn.addActionListener(e -> {
            if (0 == tableModel.getRowCount()) {
                return;
            }

            int[] selectRows = table.getSelectedRows();
            if (null == selectRows || 1 != selectRows.length) {
                return;
            }

            // todo 弹出编辑页面
        });

        selectAllBtn.addActionListener(e -> table.selectAll());

        selectNoneBtn.addActionListener(e -> table.clearSelection());
    }

    private void initActionListening() {
        initNorthBtnActionListening();
        initCenterBtnActionListening();
        initSouthBtnActionListening();
    }

    public List<ScanTaskArgs> getScanTaskArgsList() {
        return tableModel.getScanTaskArgsList();
    }
}
