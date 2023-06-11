package ui.panel.subPanel;

import entities.CommandLineColumnName;
import entities.CommandLineColumnNameIndex;
import entities.OptionsCommandLine;
import models.CommandLineTableModel;
import ui.component.CommandLineEditorDialog;
import ui.component.ScanOptionsTipsDialog;
import utils.Autocomplete;
import utils.GlobalStaticVariables;
import utils.MessageUtil;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

import static utils.GlobalStaticVariables.EX_MSG;
import static utils.GlobalStaticVariables.SCAN_OPTIONS_HELP_TEXT;

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
    JButton configDefaultBtn;

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

        MessageUtil messageUtil = EX_MSG;

        northPanel = new JPanel(new BorderLayout());

        commandLineOperationPanel = new JPanel(new BorderLayout());

        tagContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        tagLabel = new JLabel(messageUtil.getMsg("tag"));
        tagTextField = new JTextField(32);
        tagContainerPanel.add(tagLabel);
        tagContainerPanel.add(tagTextField);

        commandLineOperationPanel.add(tagContainerPanel, BorderLayout.NORTH);

        commandLineContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        commandLineLabel = new JLabel(messageUtil.getMsg("commandLine"));

        commandLineTextField = new JTextField(64);
        commandLineTextField.setFocusTraversalKeysEnabled(false);
        Autocomplete autoComplete = new Autocomplete(commandLineTextField, GlobalStaticVariables.SCAN_OPTIONS_KEYWORDS);
        commandLineTextField.getDocument().addDocumentListener(autoComplete);
        commandLineTextField.getInputMap().put(KeyStroke.getKeyStroke("TAB"), GlobalStaticVariables.COMMIT_ACTION);
        commandLineTextField.getActionMap().put(GlobalStaticVariables.COMMIT_ACTION, autoComplete.new CommitAction());


        scanOptionsHelperBtn = new JButton(messageUtil.getMsg("scanOptionHelper"));

        commandLineContainerPanel.add(commandLineLabel);
        commandLineContainerPanel.add(commandLineTextField);
        commandLineContainerPanel.add(scanOptionsHelperBtn);

        commandLineOperationPanel.add(commandLineContainerPanel, BorderLayout.CENTER);

        preOperationContainerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addBtn = new JButton(messageUtil.getMsg("add"));
        resetBtn = new JButton(messageUtil.getMsg("reset"));
        preOperationContainerPanel.add(addBtn);
        preOperationContainerPanel.add(resetBtn);

        commandLineOperationPanel.add(preOperationContainerPanel, BorderLayout.SOUTH);

        northPanel.add(commandLineOperationPanel, BorderLayout.CENTER);

        filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        filterLabel = new JLabel(messageUtil.getMsg("by"));

        filterComboBox = new JComboBox<>();
        filterComboBox.addItem(messageUtil.getMsg("index"));
        filterComboBox.addItem(messageUtil.getMsg("tag"));
        filterComboBox.addItem(messageUtil.getMsg("commandLine"));

        filterTextField = new JTextField("", 64);

        filterBtn = new JButton(messageUtil.getMsg("filter"));
        configDefaultBtn = new JButton(messageUtil.getMsg("setDefault"));

        filterPanel.add(filterLabel);
        filterPanel.add(filterComboBox);
        filterPanel.add(filterTextField);
        filterPanel.add(filterBtn);
        filterPanel.add(configDefaultBtn);

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

        deleteBtn = new JButton(messageUtil.getMsg("delete"));
        updateBtn = new JButton(messageUtil.getMsg("update"));
        selectAllBtn = new JButton(messageUtil.getMsg("selectAll"));
        selectNoneBtn = new JButton(messageUtil.getMsg("selectNone"));

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

        if (selectedObject.equals(CommandLineColumnName.ID)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, CommandLineColumnNameIndex.ID_INDEX));

        } else if (selectedObject.equals(CommandLineColumnName.TAG)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, CommandLineColumnNameIndex.TAG_INDEX));

        } else if (selectedObject.equals(CommandLineColumnName.COMMAND_LINE)) {
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

        configDefaultBtn.addActionListener(e -> {
            if (0 == tableModel.getRowCount()) {
                return;
            }
            int[] rows = table.getSelectedRows();
            if (null == rows || 1 != rows.length) {
                return;
            }

            int row = rows[0];

            OptionsCommandLine optionsCommandLine = tableModel.getOptionsCommandLineById(row);
            if (null == optionsCommandLine) {
                return;
            }

            String cmdLineStr = optionsCommandLine.getCommandLineStr();
            if (null == cmdLineStr || cmdLineStr.trim().isEmpty()) {
                return;
            }

            GlobalStaticVariables.DEFAULT_COMMAND_LINE_STR = cmdLineStr;
            tableModel.updateWasDefaultById(row, Boolean.TRUE);
        });
    }

    private void initCenterBtnActionListening() {
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                super.mouseClicked(e);

                int col = table.getSelectedColumn();


                if (CommandLineColumnNameIndex.ID_INDEX == tableModel.getRowCount()) {
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

                if (2 == e.getClickCount() && 0 == col) {
                    // 弹出参数详情
                    CommandLineEditorDialog commandLineEditorDialog = new CommandLineEditorDialog(tableModel, selectRows[0], false);
                    commandLineEditorDialog.setVisible(true);
                }

            }
        });

        table.getModel().addTableModelListener(e -> {
            int col = e.getColumn();
            int row = e.getFirstRow();
            OptionsCommandLine optionsCommandLine0 = tableModel.getOptionsCommandLineById(row);

            if (CommandLineColumnNameIndex.COMMAND_LINE_STR_INDEX == col) {

                if (Boolean.FALSE.equals(optionsCommandLine0.getWasDefault())) {
                    return;
                }

                if (TableModelEvent.UPDATE != e.getType()) {
                    return;
                }

                GlobalStaticVariables.DEFAULT_COMMAND_LINE_STR = optionsCommandLine0.getCommandLineStr();

                return;
            }


            if (null == optionsCommandLine0) {
                return;
            }

            Boolean tmp = optionsCommandLine0.getWasDefault();
            if (null == tmp) {
                return;
            }

            if (Boolean.FALSE.equals(optionsCommandLine0.getWasDefault())) {
                int cnt = 0;
                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    if (Boolean.FALSE.equals(tableModel.getOptionsCommandLineById(i).getWasDefault())) {
                        cnt++;
                    }
                }
                if (cnt == tableModel.getRowCount()) {
                    GlobalStaticVariables.DEFAULT_COMMAND_LINE_STR = "";
                }

                return;
            }

            String cmdLine = optionsCommandLine0.getCommandLineStr();
            if (null != cmdLine && !cmdLine.trim().isEmpty()) {
                GlobalStaticVariables.DEFAULT_COMMAND_LINE_STR = cmdLine;
            }

            SwingUtilities.invokeLater(() -> {
                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    if (i != row) {
                        OptionsCommandLine optionsCommandLine = tableModel.getOptionsCommandLineById(i);
                        optionsCommandLine.setWasDefault(Boolean.FALSE);
                        tableModel.fireTableCellUpdated(i, col);
                    }
                }
            });

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

    public void updateI18n(MessageUtil messageUtil) {
        // todo reset table columns name or we say headers name
        tableModel.updateI18n();


        tagLabel.setText(messageUtil.getMsg("tag"));
        commandLineLabel.setText(messageUtil.getMsg("commandLine"));
        scanOptionsHelperBtn.setText(messageUtil.getMsg("scanOptionHelper"));

        addBtn.setText(messageUtil.getMsg("add"));
        resetBtn.setText(messageUtil.getMsg("reset"));

        filterLabel.setText(messageUtil.getMsg("by"));

        filterComboBox.removeAllItems();
        filterComboBox.addItem(messageUtil.getMsg("index"));
        filterComboBox.addItem(messageUtil.getMsg("tag"));
        filterComboBox.addItem(messageUtil.getMsg("commandLine"));

        filterBtn.setText(messageUtil.getMsg("filter"));

        configDefaultBtn.setText(messageUtil.getMsg("setDefault"));

        deleteBtn.setText(messageUtil.getMsg("delete"));
        updateBtn.setText(messageUtil.getMsg("update"));
        selectAllBtn.setText(messageUtil.getMsg("selectAll"));
        selectNoneBtn.setText(messageUtil.getMsg("selectNone"));

    }
}
