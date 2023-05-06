package models;

import entities.ScanTask;
import entities.ScanTaskColumnName;
import entities.ScanTaskResultDetail;
import entities.ScanTaskStatus;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;


public class ScanTaskTableModel extends AbstractTableModel {
    static final ArrayList<ScanTask> scanTaskArrayList = new ArrayList<>();
    static final int STATIC_COLUMN_COUNT = 11;

    @Override
    public int getRowCount() {
        return scanTaskArrayList.size();
    }

    @Override
    public int getColumnCount() {
        return STATIC_COLUMN_COUNT;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (0 == scanTaskArrayList.size() || (rowIndex >= scanTaskArrayList.size() || 0 > rowIndex) || (0 > columnIndex || STATIC_COLUMN_COUNT <= columnIndex)) {
            return null;
        }

        ScanTask scanTask = scanTaskArrayList.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return scanTask.getId();
            case 1:
                return scanTask.getName();
            case 2:
                return scanTask.getMethod();
            case 3:
                return scanTask.getHost();
            case 4:
                return scanTask.getPort();
            case 5:
                return scanTask.getUrl();
            case 6:
                return scanTask.getResponseStatusCode();
            case 7:
                return scanTask.getResponseContentLength();
            case 8:
                return scanTask.getTaskStatus().toString();
            case 9:
                return scanTask.getInjected().toString();
            case 10:
                return scanTask.getComment();
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
                return ScanTaskColumnName.ID.toString();
            case 1:
                return ScanTaskColumnName.NAME.toString();
            case 2:
                return ScanTaskColumnName.METHOD.toString();
            case 3:
                return ScanTaskColumnName.HOST.toString();
            case 4:
                return ScanTaskColumnName.PORT.toString();
            case 5:
                return ScanTaskColumnName.URL.toString();
            case 6:
                return ScanTaskColumnName.RESPONSE_STATUS_CODE.toString();
            case 7:
                return ScanTaskColumnName.RESPONSE_CONTENT_LENGTH.toString();
            case 8:
                return ScanTaskColumnName.TASK_STATUS.toString();
            case 9:
                return ScanTaskColumnName.INJECTED.toString();
            case 10:
                return ScanTaskColumnName.COMMENT.toString();

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
            case 4:
            case 6:
            case 7:
                return Integer.class;
            case 1:
            case 2:
            case 3:
            case 5:
            case 8:
            case 9:
            case 10:
                return String.class;
            default:
                return null;
        }
    }

    public synchronized void AddNewScanTask(ScanTask scanTask) {
        scanTaskArrayList.add(scanTask);

        final int index = scanTaskArrayList.size() - 1;
        SwingUtilities.invokeLater(() -> fireTableRowsInserted(index, index));
    }

    public void deleteScanTask(ScanTask scanTask) {
        scanTaskArrayList.remove(scanTask);
        SwingUtilities.invokeLater(this::fireTableDataChanged);
    }

    public ScanTask getScanTaskById(int id) {
        for (ScanTask scanTask : scanTaskArrayList) {
            if (scanTask.getId() == id) {
                return scanTask;
            }
        }
        return null;
    }


    public void updateScanTaskScanTaskStatusById(int id, ScanTaskStatus scanTaskStatus) {
        if (id < 0 || id >= scanTaskArrayList.size() || null == scanTaskStatus) {
            return;
        }

        scanTaskArrayList.get(id).setTaskStatus(scanTaskStatus);
    }

    public ScanTaskStatus getScanTaskStatusById(int id) {
        if (id < 0 || id >= scanTaskArrayList.size()) {
            return null;
        }

        return scanTaskArrayList.get(id).getTaskStatus();
    }

    public void setScanTaskScanTaskResultDetailById(int id, ScanTaskResultDetail scanTaskResultDetail) {
        if (id < 0 || id >= scanTaskArrayList.size() || null == scanTaskResultDetail) {
            return;
        }

        scanTaskArrayList.get(id).setScanTaskResultDetail(scanTaskResultDetail);
    }

    public ScanTaskResultDetail getScanTaskResultDetailById(int id) {
        if (id < 0 || id >= scanTaskArrayList.size()) {
            return null;
        }
        return scanTaskArrayList.get(id).getScanTaskResultDetail();
    }

    public int getNewScanTaskId() {
        return scanTaskArrayList.size();
    }

}
