package models;

import entities.ScanTaskArgsColumnName;
import entities.ScanTaskOptionsCommandLine;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class ScanTaskCommandLineTableModel extends AbstractTableModel {
    List<ScanTaskOptionsCommandLine> scanTaskOptionsCommandLineList = new ArrayList<>();
    static final int STATIC_COLUMN_COUNT = 3;

    public void setScanTaskArgsList(List<ScanTaskOptionsCommandLine> scanTaskOptionsCommandLineList) {
        this.scanTaskOptionsCommandLineList = scanTaskOptionsCommandLineList;
    }

    @Override
    public int getRowCount() {
        return scanTaskOptionsCommandLineList.size();
    }

    @Override
    public int getColumnCount() {
        return STATIC_COLUMN_COUNT;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (0 == scanTaskOptionsCommandLineList.size() || (0 > rowIndex || rowIndex >= scanTaskOptionsCommandLineList.size()) || (0 > columnIndex || STATIC_COLUMN_COUNT <= columnIndex)) {
            return null;
        }

        ScanTaskOptionsCommandLine scanTaskOptionsCommandLine = scanTaskOptionsCommandLineList.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return scanTaskOptionsCommandLine.getId();
            case 1:
                return scanTaskOptionsCommandLine.getTag();
            case 2:
                return scanTaskOptionsCommandLine.getCommandLineStr();
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
            case 0:
                return ScanTaskArgsColumnName.ID.toString();
            case 1:
                return ScanTaskArgsColumnName.TAG.toString();
            case 2:
                return ScanTaskArgsColumnName.ARGS_STR.toString();

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
            case 2:
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
        if (null == obj || 0 > row || scanTaskOptionsCommandLineList.size() < row || 0 >= col || STATIC_COLUMN_COUNT <= col) {
            return;
        }

        ScanTaskOptionsCommandLine scanTaskOptionsCommandLine = scanTaskOptionsCommandLineList.get(row);
        switch (col) {
            case 1:
                SwingUtilities.invokeLater(() -> {
                    scanTaskOptionsCommandLine.setTag((String) obj);
                    fireTableCellUpdated(row, col);
                });
                break;
            case 2:
                SwingUtilities.invokeLater(() -> {
                    scanTaskOptionsCommandLine.setCommandLineStr((String) obj);
                    fireTableCellUpdated(row, col);
                });
                break;
            default:
                break;
        }

    }

    public void addScanTaskOptionsCommandLine(ScanTaskOptionsCommandLine scanTaskOptionsCommandLine) {
        if (null == scanTaskOptionsCommandLine) {
            return;
        }
        int id = scanTaskOptionsCommandLine.getId();
        SwingUtilities.invokeLater(() -> {
            scanTaskOptionsCommandLineList.add(scanTaskOptionsCommandLine);
            fireTableRowsInserted(id, id);
        });
    }

    public void addScanTaskOptionsCommandLine(String tag, String argsStr) {
        SwingUtilities.invokeLater(() -> {
            int id = scanTaskOptionsCommandLineList.size();
            scanTaskOptionsCommandLineList.add(new ScanTaskOptionsCommandLine(id, tag, argsStr));
            fireTableRowsInserted(id, id);
        });
    }

    public void addScanTaskOptionsCommandLine(int id, String tag, String argsStr) {
        SwingUtilities.invokeLater(() -> {
            scanTaskOptionsCommandLineList.add(new ScanTaskOptionsCommandLine(id, tag, argsStr));
            fireTableRowsInserted(id, id);
        });
    }

    public synchronized void deleteScanTaskOptionsCommandLineById(int id) {
        if (0 == scanTaskOptionsCommandLineList.size() || (0 > id || id > scanTaskOptionsCommandLineList.size())) {
            return;
        }

//        scanTaskOptionsCommandLineList.remove(id);
//        fireTableRowsDeleted(id, id);

        SwingUtilities.invokeLater(() -> {
            scanTaskOptionsCommandLineList.remove(id);
            fireTableRowsDeleted(id, id);
        });
    }

    public boolean updateTagById(int id, String tag) {
        if (0 == scanTaskOptionsCommandLineList.size() || (0 > id || id >= scanTaskOptionsCommandLineList.size()) || (null == tag || tag.trim().isEmpty())) {
            return false;
        }

        scanTaskOptionsCommandLineList.get(id).setTag(tag.trim());

        return true;
    }

    public boolean updateCommandLinesById(int id, String commandLineStr) {
        if (0 == scanTaskOptionsCommandLineList.size() || (0 > id || id >= scanTaskOptionsCommandLineList.size()) || (null == commandLineStr || commandLineStr.trim().isEmpty())) {
            return false;
        }

        scanTaskOptionsCommandLineList.get(id).setCommandLineStr(commandLineStr);
        return true;
    }

    public ScanTaskOptionsCommandLine getScanTaskOptionsCommandLineById(int id) {
        if (0 == scanTaskOptionsCommandLineList.size() || (0 > id || id >= scanTaskOptionsCommandLineList.size())) {
            return null;
        }

        return scanTaskOptionsCommandLineList.get(id);
    }

    public ScanTaskOptionsCommandLine getScanTaskOptionsCommandLineByTag(String tag) {
        if (0 == scanTaskOptionsCommandLineList.size() || (null == tag || tag.trim().isEmpty())) {
            return null;
        }

        for (ScanTaskOptionsCommandLine scanTaskOptionsCommandLine : scanTaskOptionsCommandLineList) {
            if (scanTaskOptionsCommandLine.getTag().equals(tag)) {
                return scanTaskOptionsCommandLine;
            }
        }

        return null;
    }

    public List<ScanTaskOptionsCommandLine> getScanTaskOptionsCommandLineList() {
        return scanTaskOptionsCommandLineList;
    }

    public boolean isTagExist(String tagStr) {
        for (ScanTaskOptionsCommandLine scanTaskOptionsCommandLine : scanTaskOptionsCommandLineList) {
            if (scanTaskOptionsCommandLine.getTag().equals(tagStr)) {
                return true;
            }
        }
        return false;
    }


}
