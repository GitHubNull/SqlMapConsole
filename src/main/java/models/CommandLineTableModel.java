package models;

import entities.CommandLineColumnName;
import entities.CommandLineColumnNameIndex;
import entities.OptionsCommandLine;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class CommandLineTableModel extends AbstractTableModel {
    List<OptionsCommandLine> optionsCommandLineList = new ArrayList<>();
    static final int STATIC_COLUMN_COUNT = 4;

    public void setScanTaskArgsList(List<OptionsCommandLine> optionsCommandLineList) {
        this.optionsCommandLineList = optionsCommandLineList;
    }

    @Override
    public int getRowCount() {
        return optionsCommandLineList.size();
    }

    @Override
    public int getColumnCount() {
        return STATIC_COLUMN_COUNT;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (0 == optionsCommandLineList.size() || (0 > rowIndex || rowIndex >= optionsCommandLineList.size()) || (0 > columnIndex || STATIC_COLUMN_COUNT <= columnIndex)) {
            return null;
        }

        OptionsCommandLine optionsCommandLine = optionsCommandLineList.get(rowIndex);
        switch (columnIndex) {
            case CommandLineColumnNameIndex.ID_INDEX:
                return optionsCommandLine.getId();
            case CommandLineColumnNameIndex.WAS_DEFAULT_INDEX:
                return optionsCommandLine.getWasDefault();
            case CommandLineColumnNameIndex.TAG_INDEX:
                return optionsCommandLine.getTag();
            case 3:
                return optionsCommandLine.getCommandLineStr();
            default:
                return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        if (0 > column || column >= STATIC_COLUMN_COUNT) {
            return null;
        }

        switch (column) {
            case CommandLineColumnNameIndex.ID_INDEX:
                return CommandLineColumnName.ID.toString();
            case CommandLineColumnNameIndex.WAS_DEFAULT_INDEX:
                return CommandLineColumnName.WAS_DEFAULT.toString();
            case CommandLineColumnNameIndex.TAG_INDEX:
                return CommandLineColumnName.TAG.toString();
            case CommandLineColumnNameIndex.COMMAND_LINE_STR_INDEX:
                return CommandLineColumnName.COMMAND_LINE_STR.toString();

            default:
                return null;
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (0 > columnIndex || columnIndex >= STATIC_COLUMN_COUNT) {
            return null;
        }

        switch (columnIndex) {
            case 0:
                return Integer.class;
            case 1:
                return Boolean.class;
            case 2:
            case 3:
                return String.class;
            default:
                return null;
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex != 0;
    }

    @Override
    public void setValueAt(Object obj, int row, int col) {
        if (null == obj || 0 > row || optionsCommandLineList.size() < row || 0 >= col || STATIC_COLUMN_COUNT <= col) {
            return;
        }

        OptionsCommandLine optionsCommandLine = optionsCommandLineList.get(row);
        switch (col) {
            case CommandLineColumnNameIndex.WAS_DEFAULT_INDEX:
                SwingUtilities.invokeLater(() -> {
                    optionsCommandLine.setWasDefault((Boolean) obj);
                    fireTableCellUpdated(row, col);
                });
                break;
            case CommandLineColumnNameIndex.TAG_INDEX:
                SwingUtilities.invokeLater(() -> {
                    optionsCommandLine.setTag((String) obj);
                    fireTableCellUpdated(row, col);
                });
                break;
            case CommandLineColumnNameIndex.COMMAND_LINE_STR_INDEX:
                SwingUtilities.invokeLater(() -> {
                    optionsCommandLine.setCommandLineStr((String) obj);
                    fireTableCellUpdated(row, col);
                });
                break;
            default:
                break;
        }

    }

    public void addOptionsCommandLine(OptionsCommandLine optionsCommandLine) {
        if (null == optionsCommandLine) {
            return;
        }
        int id = optionsCommandLine.getId();
        SwingUtilities.invokeLater(() -> {
            optionsCommandLineList.add(optionsCommandLine);
            fireTableRowsInserted(id, id);
        });
    }

    public void addOptionsCommandLine(String tag, String argsStr) {
        SwingUtilities.invokeLater(() -> {
            int id = optionsCommandLineList.size();
            optionsCommandLineList.add(new OptionsCommandLine(id, tag, argsStr, false));
            fireTableRowsInserted(id, id);
        });
    }

    public synchronized void deleteOptionsCommandLineById(int id) {
        if (0 == optionsCommandLineList.size() || (0 > id || id > optionsCommandLineList.size())) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            optionsCommandLineList.remove(id);
            fireTableRowsDeleted(id, id);
        });
    }

    public void updateWasDefaultById(int id, Boolean wasDefault) {
        if (0 == optionsCommandLineList.size() || (0 > id || id >= optionsCommandLineList.size())) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            optionsCommandLineList.get(id).setWasDefault(wasDefault);
            fireTableCellUpdated(id, 1);
        });

    }

    public void updateTagById(int id, String tag) {
        if (0 == optionsCommandLineList.size() || (0 > id || id >= optionsCommandLineList.size()) || (null == tag || tag.trim().isEmpty())) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            optionsCommandLineList.get(id).setTag(tag.trim());
            fireTableCellUpdated(id, 2);
        });

    }

    public void updateCommandLinesById(int id, String commandLineStr) {
        if (0 == optionsCommandLineList.size() || (0 > id || id >= optionsCommandLineList.size()) || (null == commandLineStr || commandLineStr.trim().isEmpty())) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            optionsCommandLineList.get(id).setCommandLineStr(commandLineStr);
            fireTableCellUpdated(id, 3);
        });
    }

    public OptionsCommandLine getOptionsCommandLineById(int id) {
        if (0 == optionsCommandLineList.size() || (0 > id || id >= optionsCommandLineList.size())) {
            return null;
        }

        return optionsCommandLineList.get(id);
    }

    public List<OptionsCommandLine> getOptionsCommandLineList() {
        return optionsCommandLineList;
    }

    public boolean isTagExist(String tagStr) {
        for (OptionsCommandLine optionsCommandLine : optionsCommandLineList) {
            if (optionsCommandLine.getTag().equals(tagStr)) {
                return true;
            }
        }
        return false;
    }


}
