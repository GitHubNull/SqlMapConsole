package models;

import entities.ScanTaskArgs;
import entities.ScanTaskArgsColumnName;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class ScanTaskArgsTableModel extends AbstractTableModel {
    List<ScanTaskArgs> scanTaskArgsList = new ArrayList<>();
    static final int STATIC_COLUMN_COUNT = 3;

    public void setScanTaskArgsList(List<ScanTaskArgs> scanTaskArgsList) {
        this.scanTaskArgsList = scanTaskArgsList;
    }

    @Override
    public int getRowCount() {
        return scanTaskArgsList.size();
    }

    @Override
    public int getColumnCount() {
        return STATIC_COLUMN_COUNT;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (0 == scanTaskArgsList.size() || (0 > rowIndex || rowIndex >= scanTaskArgsList.size()) || (0 > columnIndex || STATIC_COLUMN_COUNT <= columnIndex)) {
            return null;
        }

        ScanTaskArgs scanTaskArgs = scanTaskArgsList.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return scanTaskArgs.getId();
            case 1:
                return scanTaskArgs.getTag();
            case 2:
                return scanTaskArgs.getArgsStr();
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
        if (null == obj || 0 > row || scanTaskArgsList.size() < row || 0 >= col || STATIC_COLUMN_COUNT <= col) {
            return;
        }

        ScanTaskArgs scanTaskArgs = scanTaskArgsList.get(row);
        switch (col) {
            case 1:
                SwingUtilities.invokeLater(() -> {
                    scanTaskArgs.setTag((String) obj);
                    fireTableCellUpdated(row, col);
                });
                break;
            case 2:
                SwingUtilities.invokeLater(() -> {
                    scanTaskArgs.setArgsStr((String) obj);
                    fireTableCellUpdated(row, col);
                });
                break;
            default:
                break;
        }

    }

    public void addScanTaskArgs(ScanTaskArgs scanTaskArgs) {
        if (null == scanTaskArgs) {
            return;
        }
        int id = scanTaskArgs.getId();
        SwingUtilities.invokeLater(() -> {
            scanTaskArgsList.add(scanTaskArgs);
            fireTableRowsInserted(id, id);
        });
    }

    public void addScanTaskArgs(String tag, String argsStr) {
        SwingUtilities.invokeLater(() -> {
            int id = scanTaskArgsList.size();
            scanTaskArgsList.add(new ScanTaskArgs(id, tag, argsStr));
            fireTableRowsInserted(id, id);
        });
    }

    public void addScanTaskArgs(int id, String tag, String argsStr) {
        SwingUtilities.invokeLater(() -> {
            scanTaskArgsList.add(new ScanTaskArgs(id, tag, argsStr));
            fireTableRowsInserted(id, id);
        });
    }

    public synchronized void deleteScanTaskArgsById(int id) {
        if (0 == scanTaskArgsList.size() || (0 > id || id > scanTaskArgsList.size())) {
            return;
        }

//        scanTaskArgsList.remove(id);
//        fireTableRowsDeleted(id, id);

        SwingUtilities.invokeLater(() -> {
            scanTaskArgsList.remove(id);
            fireTableRowsDeleted(id, id);
        });
    }

    public boolean updateTagById(int id, String tag) {
        if (0 == scanTaskArgsList.size() || (0 > id || id >= scanTaskArgsList.size()) || (null == tag || tag.trim().isEmpty())) {
            return false;
        }

        scanTaskArgsList.get(id).setTag(tag.trim());

        return true;
    }

    public boolean updateArgsById(int id, String argsStr) {
        if (0 == scanTaskArgsList.size() || (0 > id || id >= scanTaskArgsList.size()) || (null == argsStr || argsStr.trim().isEmpty())) {
            return false;
        }

        scanTaskArgsList.get(id).setArgsStr(argsStr);
        return true;
    }

    public ScanTaskArgs getScanTaskArgsById(int id) {
        if (0 == scanTaskArgsList.size() || (0 > id || id >= scanTaskArgsList.size())) {
            return null;
        }

        return scanTaskArgsList.get(id);
    }

    public ScanTaskArgs getScanTaskArgsByTag(String tag) {
        if (0 == scanTaskArgsList.size() || (null == tag || tag.trim().isEmpty())) {
            return null;
        }

        for (ScanTaskArgs scanTaskArgs : scanTaskArgsList) {
            if (scanTaskArgs.getTag().equals(tag)) {
                return scanTaskArgs;
            }
        }

        return null;
    }

    public List<ScanTaskArgs> getScanTaskArgsList() {
        return scanTaskArgsList;
    }

    public boolean isTagExist(String tagStr) {
        for (ScanTaskArgs scanTaskArgs : scanTaskArgsList) {
            if (scanTaskArgs.getTag().equals(tagStr)) {
                return true;
            }
        }
        return false;
    }


}
