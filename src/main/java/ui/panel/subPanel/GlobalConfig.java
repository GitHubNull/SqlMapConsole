package ui.panel.subPanel;

import entities.ScanTaskOptionsCommandLine;
import models.ScanTaskCommandLineTableModel;
import utils.Autocomplete;
import utils.GlobalStaticsVar;

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


    JPanel commandLineContainerPanel;
    JLabel commandLineLabel;
    JTextField commandLineTextFiled;
//    List<String> keywords;

    JPanel preOperationContainerPanel;
    JButton addBtn;
    JButton resetBtn;

    JScrollPane centerPanel;
    JTable table;
    ScanTaskCommandLineTableModel tableModel;


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

        commandLineContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        commandLineLabel = new JLabel("参数");

        commandLineTextFiled = new JTextField(64);
        commandLineTextFiled.setFocusTraversalKeysEnabled(false);
        Autocomplete autoComplete = new Autocomplete(commandLineTextFiled, GlobalStaticsVar.SCAN_OPTIONS_KEYWORDS);
        commandLineTextFiled.getDocument().addDocumentListener(autoComplete);
        commandLineTextFiled.getInputMap().put(KeyStroke.getKeyStroke("TAB"), utils.GlobalStaticsVar.COMMIT_ACTION);
        commandLineTextFiled.getActionMap().put(utils.GlobalStaticsVar.COMMIT_ACTION, autoComplete.new CommitAction());


        commandLineContainerPanel.add(commandLineLabel);
        commandLineContainerPanel.add(commandLineTextFiled);

        northPanel.add(commandLineContainerPanel, BorderLayout.CENTER);

        preOperationContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton("新增");
        resetBtn = new JButton("重置");
        preOperationContainerPanel.add(addBtn);
        preOperationContainerPanel.add(resetBtn);

        northPanel.add(preOperationContainerPanel, BorderLayout.SOUTH);

        add(northPanel, BorderLayout.NORTH);


        table = new JTable();
        tableModel = new ScanTaskCommandLineTableModel();
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
            String argsStr = commandLineTextFiled.getText();

            if (null == tagStr || null == argsStr || tagStr.trim().isEmpty() || argsStr.trim().isEmpty()) {
                return;
            }
            // 校验tag是否重复,重复则不添加
            if (tableModel.isTagExist(tagStr)) {
                return;
            }

            // todo 校验参数合法性

            tableModel.addScanTaskOptionsCommandLine(tagStr, argsStr);
        });

        resetBtn.addActionListener(e -> {
            tagTextField.setText("");
            commandLineTextFiled.setText("");
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
                tableModel.deleteScanTaskOptionsCommandLineById(selectRow);
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

    public List<ScanTaskOptionsCommandLine> getScanTaskArgsList() {
        return tableModel.getScanTaskOptionsCommandLineList();
    }
}
