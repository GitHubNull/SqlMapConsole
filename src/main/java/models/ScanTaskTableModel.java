package models;

import entities.Injected;
import entities.ScanTask;
import entities.ScanTaskColumnName;
import entities.ScanTaskStatus;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

import static entities.ScanTaskColumnNameIndex.*;


public class ScanTaskTableModel extends AbstractTableModel {
    static final ArrayList<ScanTask> scanTaskArrayList = new ArrayList<>();
    static final int STATIC_COLUMN_COUNT = 13;

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
            case ID_INDEX:
                return scanTask.getId();
            case TASK_ID_INDEX:
                return scanTask.getTaskId();
            case NAME_INDEX:
                return scanTask.getName();
            case METHOD_INDEX:
                return scanTask.getMethod();
            case HOST_INDEX:
                return scanTask.getHost();
            case PORT_INDEX:
                return scanTask.getPort();
            case URL_INDEX:
                return scanTask.getUrl();
            case RESPONSE_STATUS_CODE_INDEX:
                return scanTask.getResponseStatusCode();
            case RESPONSE_CONTENT_LENGTH_INDEX:
                return scanTask.getResponseContentLength();
            case CMD_LINE_INDEX:
                return scanTask.getCmdLine();
            case TASK_STATUS_INDEX:
                return scanTask.getTaskStatus().toString();
            case INJECTED_INDEX:
                return scanTask.getInjected();
            case COMMENT_INDEX:
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
            case ID_INDEX:
                return ScanTaskColumnName.ID.toString();
            case TASK_ID_INDEX:
                return ScanTaskColumnName.TASK_ID.toString();
            case NAME_INDEX:
                return ScanTaskColumnName.NAME.toString();
            case METHOD_INDEX:
                return ScanTaskColumnName.METHOD.toString();
            case HOST_INDEX:
                return ScanTaskColumnName.HOST.toString();
            case PORT_INDEX:
                return ScanTaskColumnName.PORT.toString();
            case URL_INDEX:
                return ScanTaskColumnName.URL.toString();
            case RESPONSE_STATUS_CODE_INDEX:
                return ScanTaskColumnName.RESPONSE_STATUS_CODE.toString();
            case RESPONSE_CONTENT_LENGTH_INDEX:
                return ScanTaskColumnName.RESPONSE_CONTENT_LENGTH.toString();
            case CMD_LINE_INDEX:
                return ScanTaskColumnName.CMD_LINE.toString();
            case TASK_STATUS_INDEX:
                return ScanTaskColumnName.TASK_STATUS.toString();
            case INJECTED_INDEX:
                return ScanTaskColumnName.INJECTED.toString();
            case COMMENT_INDEX:
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
            case ID_INDEX:
            case PORT_INDEX:
            case RESPONSE_STATUS_CODE_INDEX:
            case RESPONSE_CONTENT_LENGTH_INDEX:
                return Integer.class;
            case TASK_ID_INDEX:
            case NAME_INDEX:
            case METHOD_INDEX:
            case HOST_INDEX:
            case URL_INDEX:
            case CMD_LINE_INDEX:
            case TASK_STATUS_INDEX:
            case INJECTED_INDEX:
            case COMMENT_INDEX:
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

    public void flushScanTaskStatus() {
        for (ScanTask scanTask : scanTaskArrayList) {
            SwingUtilities.invokeLater(() -> {
                scanTask.setTaskStatus(ScanTaskStatus.STOPPED);
                fireTableCellUpdated(scanTask.getId(), TASK_STATUS_INDEX);
            });
        }
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

        SwingUtilities.invokeLater(() -> {
            scanTaskArrayList.get(id).setTaskStatus(scanTaskStatus);
            fireTableCellUpdated(id, TASK_STATUS_INDEX);
        });
    }

    public void updateScanTaskScanTaskInjectedById(int index, Injected injected) {
        if (scanTaskArrayList.isEmpty() || 0 > index || index == scanTaskArrayList.size()) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            scanTaskArrayList.get(index).setInjected(injected);
            fireTableCellUpdated(index, INJECTED_INDEX);
        });


    }

    public int getNewScanTaskId() {
        return scanTaskArrayList.size();
    }

}
