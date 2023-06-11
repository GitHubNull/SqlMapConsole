package models;

import entities.ScanTask;
import entities.ScanTaskStatus;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static entities.ScanTaskColumnNameIndex.*;
import static utils.GlobalStaticVariables.EX_MSG;


public class ScanTaskTableModel extends AbstractTableModel {
    static final ArrayList<ScanTask> scanTaskArrayList = new ArrayList<>();
    private ReentrantReadWriteLock reentrantReadWriteLock = new ReentrantReadWriteLock();
    static final int STATIC_COLUMN_COUNT = 13;
    private static String[] columnNames = new String[]{
            EX_MSG.getMsg("index"),
            EX_MSG.getMsg("taskId"),
            EX_MSG.getMsg("taskName"),
            EX_MSG.getMsg("method"),
            EX_MSG.getMsg("host"),
            EX_MSG.getMsg("port"),
            EX_MSG.getMsg("url"),
            EX_MSG.getMsg("status_code"),
            EX_MSG.getMsg("content_length"),
            EX_MSG.getMsg("commandLine"),
            EX_MSG.getMsg("task_status"),
            EX_MSG.getMsg("injectionStatus"),
            EX_MSG.getMsg("comment")
    };

    @Override
    public int getRowCount() {
        int index;
        reentrantReadWriteLock.readLock().lock();
        try {
            index = scanTaskArrayList.size();
        } finally {
            reentrantReadWriteLock.readLock().unlock();
        }
        return index;
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
                return scanTask.getTaskStatus();
            case INJECTED_INDEX:
                return scanTask.getInjectionStatus();
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

        return columnNames[column];
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
        reentrantReadWriteLock.writeLock().lock();
        try {
            scanTaskArrayList.add(scanTask);
        } finally {
            reentrantReadWriteLock.writeLock().unlock();
        }

        final int index = scanTaskArrayList.size() - 1;
        SwingUtilities.invokeLater(() -> fireTableRowsInserted(index, index));
    }

    public void deleteScanTask(ScanTask scanTask) {
        reentrantReadWriteLock.writeLock().lock();
        try {
            scanTaskArrayList.remove(scanTask);
        } finally {
            reentrantReadWriteLock.writeLock().unlock();
        }

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
        reentrantReadWriteLock.readLock().lock();
        try {
            for (ScanTask scanTask : scanTaskArrayList) {
                if (scanTask.getId() == id) {
                    return scanTask;
                }
            }
        } finally {
            reentrantReadWriteLock.readLock().unlock();
        }
        return null;
    }


    public void updateScanTaskScanTaskStatusById(int id, String scanTaskStatus) {
        if (id < 0 || id >= scanTaskArrayList.size() || null == scanTaskStatus) {
            return;
        }

        reentrantReadWriteLock.writeLock().lock();
        try {
            scanTaskArrayList.get(id).setTaskStatus(scanTaskStatus);
        } finally {
            reentrantReadWriteLock.writeLock().unlock();
        }

        SwingUtilities.invokeLater(() -> {
            fireTableCellUpdated(id, TASK_STATUS_INDEX);
        });
    }

    public void updateScanTaskScanTaskInjectedById(int index, String injectionStatus) {
        if (scanTaskArrayList.isEmpty() || 0 > index || index == scanTaskArrayList.size()) {
            return;
        }

        reentrantReadWriteLock.writeLock().lock();
        try {
            scanTaskArrayList.get(index).setInjectionStatus(injectionStatus);
        } finally {
            reentrantReadWriteLock.writeLock().unlock();
        }

        SwingUtilities.invokeLater(() -> {
            fireTableCellUpdated(index, INJECTED_INDEX);
        });


    }

    public int getNewScanTaskId() {
        int index;
        reentrantReadWriteLock.readLock().lock();
        try {
            index = scanTaskArrayList.size();
        } finally {
            reentrantReadWriteLock.readLock().unlock();
        }
        return index;
    }

    public void updateI18n() {
        columnNames = new String[]{
                EX_MSG.getMsg("index"),
                EX_MSG.getMsg("taskId"),
                EX_MSG.getMsg("taskName"),
                EX_MSG.getMsg("method"),
                EX_MSG.getMsg("host"),
                EX_MSG.getMsg("port"),
                EX_MSG.getMsg("url"),
                EX_MSG.getMsg("status_code"),
                EX_MSG.getMsg("content_length"),
                EX_MSG.getMsg("commandLine"),
                EX_MSG.getMsg("task_status"),
                EX_MSG.getMsg("injectionStatus"),
                EX_MSG.getMsg("comment")
        };

        SwingUtilities.invokeLater(() -> {
            fireTableStructureChanged();
        });


    }

}
