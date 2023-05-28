package ui.panel.subPanel;

import entities.CommandLineColumnName;
import entities.CommandLineColumnNameIndex;
import entities.OptionsCommandLine;
import models.CommandLineTableModel;
import ui.component.CommandLineEditorDialog;
import ui.component.ScanOptionsTipsDialog;
import utils.Autocomplete;
import utils.GlobalStaticsVar;

import javax.swing.*;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

import static utils.GlobalStaticsVar.SCAN_OPTIONS_HELP_TEXT;

public class CommandLineManagerPanel extends JPanel {
    JPanel northPanel;

    JPanel commandLineOperationPanel;

    JPanel tagContainerPanel;
    JLabel tagLabel;
    JTextField tagTextField;


    JPanel commandLineContainerPanel;
    JLabel commandLineLabel;
    JTextField commandLineTextField;
    JButton scanOptionsHelperBtn;
//    List<String> keywords;

    JPanel preOperationContainerPanel;
    JButton addBtn;
    JButton resetBtn;

    JPanel filterPanel;
    JLabel filterLabel;
    JComboBox<String> filterComboBox;
    JTextField filterTextField;
    JButton filterBtn;

    JScrollPane centerPanel;
    JTable table;
    CommandLineTableModel tableModel;
    TableRowSorter<CommandLineTableModel> sorter;


    JPanel southPanel;
    JButton deleteBtn;
    JButton updateBtn;
    JButton selectAllBtn;
    JButton selectNoneBtn;


    public CommandLineManagerPanel() {
        setLayout(new BorderLayout());


        northPanel = new JPanel(new BorderLayout());

        commandLineOperationPanel = new JPanel(new BorderLayout());

        tagContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        tagLabel = new JLabel("标签");
        tagTextField = new JTextField(32);
        tagContainerPanel.add(tagLabel);
        tagContainerPanel.add(tagTextField);

        commandLineOperationPanel.add(tagContainerPanel, BorderLayout.NORTH);

        commandLineContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        commandLineLabel = new JLabel("参数");

        commandLineTextField = new JTextField(64);
        commandLineTextField.setFocusTraversalKeysEnabled(false);
        Autocomplete autoComplete = new Autocomplete(commandLineTextField, GlobalStaticsVar.SCAN_OPTIONS_KEYWORDS);
        commandLineTextField.getDocument().addDocumentListener(autoComplete);
        commandLineTextField.getInputMap().put(KeyStroke.getKeyStroke("TAB"), utils.GlobalStaticsVar.COMMIT_ACTION);
        commandLineTextField.getActionMap().put(utils.GlobalStaticsVar.COMMIT_ACTION, autoComplete.new CommitAction());


        scanOptionsHelperBtn = new JButton("参数列表帮助？");

        commandLineContainerPanel.add(commandLineLabel);
        commandLineContainerPanel.add(commandLineTextField);
        commandLineContainerPanel.add(scanOptionsHelperBtn);

        commandLineOperationPanel.add(commandLineContainerPanel, BorderLayout.CENTER);

        preOperationContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton("新增");
        resetBtn = new JButton("重置");
        preOperationContainerPanel.add(addBtn);
        preOperationContainerPanel.add(resetBtn);

        commandLineOperationPanel.add(preOperationContainerPanel, BorderLayout.SOUTH);

        northPanel.add(commandLineOperationPanel, BorderLayout.CENTER);

        filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        filterLabel = new JLabel("按照");

        filterComboBox = new JComboBox<>();
        filterComboBox.addItem(CommandLineColumnName.ID.toString());
        filterComboBox.addItem(CommandLineColumnName.TAG.toString());
        filterComboBox.addItem(CommandLineColumnName.COMMAND_LINE_STR.toString());

        filterTextField = new JTextField("", 64);

        filterBtn = new JButton("过滤");

        filterPanel.add(filterLabel);
        filterPanel.add(filterComboBox);
        filterPanel.add(filterTextField);
        filterPanel.add(filterBtn);

        northPanel.add(filterPanel, BorderLayout.SOUTH);

//        northPanel

        add(northPanel, BorderLayout.NORTH);


        table = new JTable();
        tableModel = new CommandLineTableModel();
        table.setModel(tableModel);

        sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

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

    private void filterTable() {
        if (0 == tableModel.getRowCount()) {
            return;
        }

        Object selectedObject = filterComboBox.getSelectedItem();
        String filterText = filterTextField.getText();
        if (null == filterText || filterText.isEmpty()) {
            sorter.setRowFilter(null);
            return;
        }

        if (null == selectedObject) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, CommandLineColumnNameIndex.TAG_INDEX));
            return;
        }

        if (selectedObject.equals(CommandLineColumnName.ID.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, CommandLineColumnNameIndex.ID_INDEX));

        } else if (selectedObject.equals(CommandLineColumnName.TAG.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, CommandLineColumnNameIndex.TAG_INDEX));

        } else if (selectedObject.equals(CommandLineColumnName.COMMAND_LINE_STR.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, CommandLineColumnNameIndex.COMMAND_LINE_STR_INDEX));

        } else {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, CommandLineColumnNameIndex.TAG_INDEX));

        }

    }

    private void initNorthBtnActionListening() {
        addBtn.addActionListener(e -> {
            String tagStr = tagTextField.getText();
            String argsStr = commandLineTextField.getText();

            if (null == tagStr || null == argsStr || tagStr.trim().isEmpty() || argsStr.trim().isEmpty()) {
                return;
            }
            // 校验tag是否重复,重复则不添加
            if (tableModel.isTagExist(tagStr)) {
                return;
            }

            // todo 校验参数合法性

            tableModel.addOptionsCommandLine(tagStr, argsStr);
        });

        resetBtn.addActionListener(e -> {
            tagTextField.setText("");
            commandLineTextField.setText("");
        });

        scanOptionsHelperBtn.addActionListener(e -> {
            ScanOptionsTipsDialog scanOptionsTipsDialog = new ScanOptionsTipsDialog(SCAN_OPTIONS_HELP_TEXT);
            scanOptionsTipsDialog.setVisible(true);
        });

        filterBtn.addActionListener(this::actionPerformed);
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

                int[] selectRows = table.getSelectedRows();
                if (null == selectRows || 1 != selectRows.length) {
                    return;
                }

                OptionsCommandLine optionsCommandLine = tableModel.getOptionsCommandLineById(selectRows[0]);
                if (null == optionsCommandLine) {
                    return;
                }

                // 弹出参数详情
                CommandLineEditorDialog commandLineEditorDialog = new CommandLineEditorDialog(tableModel, selectRows[0], false);
                commandLineEditorDialog.setVisible(true);
            }
        });
    }

    private void initSouthBtnActionListening() {
        deleteBtn.addActionListener(e -> {

            if (0 == tableModel.getRowCount()) {
                return;
            }

            int[] selectRows = table.getSelectedRows();
            if (null == selectRows) {
                return;
            }

            for (int selectRow : selectRows) {
                tableModel.deleteOptionsCommandLineById(selectRow);
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

            OptionsCommandLine optionsCommandLine = tableModel.getOptionsCommandLineById(selectRows[0]);
            if (null == optionsCommandLine) {
                return;
            }

            // 弹出编辑页面
            CommandLineEditorDialog commandLineEditorDialog = new CommandLineEditorDialog(tableModel, selectRows[0], true);
            commandLineEditorDialog.setVisible(true);

        });

        selectAllBtn.addActionListener(e -> table.selectAll());

        selectNoneBtn.addActionListener(e -> table.clearSelection());
    }

    private void initActionListening() {
        initNorthBtnActionListening();
        initCenterBtnActionListening();
        initSouthBtnActionListening();
    }

    public List<OptionsCommandLine> getOptionsCommandLineList() {
        return tableModel.getOptionsCommandLineList();
    }

    public CommandLineTableModel getTableModel() {
        return tableModel;
    }


    private void actionPerformed(ActionEvent e) {
        filterTable();
    }
}
