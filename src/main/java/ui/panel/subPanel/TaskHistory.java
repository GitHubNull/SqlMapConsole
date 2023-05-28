package ui.panel.subPanel;

import burp.*;
import com.alibaba.fastjson2.JSON;
import controller.MessageEditorController;
import entities.*;
import models.ScanTaskTableModel;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.jetbrains.annotations.NotNull;
import sqlmapApi.SqlMapApiClient;
import sqlmapApi.responsesBody.ScanKillResponse;
import sqlmapApi.responsesBody.ScanStopResponse;
import sqlmapApi.responsesBody.TaskDeleteResponse;
import ui.component.ScanResultShowDialog;
import ui.component.ScanTaskEditorDialog;

import javax.swing.*;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URL;

import static utils.GlobalStaticsVar.SQLMAPAPI_SERVICE_STOP_FLAG;
import static utils.GlobalStaticsVar.SQLMAPAPI_SERVICE_STOP_FLAG_LOCK;

public class TaskHistory extends JPanel {
    JPanel northPanel;
    JLabel filterLabel;
    JComboBox<String> filterColumnSelectionComboBox;
    JTextField filterTextField;
    JButton filterBtn;

    JButton startTaskBtn;
    JButton stopTaskBtn;
    JButton killTaskBtn;

    JButton deleteTaskBtn;
    JButton updateTaskBtn;

    JButton selectAllBtn;
    JButton selectNoneBtn;

    JSplitPane centerPanel;

    JScrollPane tableContainer;
    JTable table;
    ScanTaskTableModel scanTaskTableModel;
    TableRowSorter<ScanTaskTableModel> sorter;


    final static String REQUEST = "请求";
    final static String RESPONSE = "响应";


    JPanel messageViewRootContainer;

    JPanel messageViewStyleSwitchPanel;
    JPanel radioButtonContainer;

    ButtonGroup buttonGroup;
    JRadioButton left2RightRadioButton;
    JRadioButton top2DownRadioButton;
    JRadioButton singleRadioButton;

    JPanel messageViewPanelCardContainer;
    CardLayout cardLayout;

    final static String SINGLE_VIEW = "single";
    final static String DOUBLE_VIEW = "double";


    JTabbedPane singleMessageView;
//    JPanel doubleMessageView;

    JSplitPane doubleMessageView;

    //    JScrollPane requestViewPanel;
    IMessageEditor requestMessageEditor;

    //    JScrollPane responseViewPanel;
    IMessageEditor responseMessageEditor;

    JPanel southPanel;
    JLabel statusInfoText;

    MessageShowStyle messageShowStyle;

    enum MessageShowStyle {
        LEFT_2_RIGHT, TOP_2_DOWN, SINGLE
    }

    public TaskHistory() {
        setLayout(new BorderLayout());

        northPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        filterLabel = new JLabel("按照");

        filterColumnSelectionComboBox = new JComboBox<>();
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.ID.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.TASK_ID.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.NAME.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.METHOD.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.HOST.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.PORT.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.URL.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.RESPONSE_STATUS_CODE.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.RESPONSE_CONTENT_LENGTH.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.CMD_LINE.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.TASK_STATUS.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.INJECTED.toString());
        filterColumnSelectionComboBox.addItem(ScanTaskColumnName.COMMENT.toString());

        filterTextField = new JTextField(32);
        filterBtn = new JButton("过滤");

        northPanel.add(filterLabel);
        northPanel.add(filterColumnSelectionComboBox);
        northPanel.add(filterTextField);
        northPanel.add(filterBtn);

        startTaskBtn = new JButton("开始扫描");
        stopTaskBtn = new JButton("停止扫描");
        killTaskBtn = new JButton("杀掉扫描");

        deleteTaskBtn = new JButton("删除任务");
        updateTaskBtn = new JButton("编辑任务");

        selectAllBtn = new JButton("选择全部");
        selectNoneBtn = new JButton("全不选择");

        northPanel.add(startTaskBtn);
        northPanel.add(stopTaskBtn);
        northPanel.add(killTaskBtn);

        northPanel.add(deleteTaskBtn);
        northPanel.add(updateTaskBtn);

        northPanel.add(selectAllBtn);
        northPanel.add(selectNoneBtn);

        add(northPanel, BorderLayout.NORTH);


        table = new JTable();
        table.setAlignmentX(JTable.LEFT_ALIGNMENT);
        scanTaskTableModel = new ScanTaskTableModel();
        table.setModel(scanTaskTableModel);
        tableContainer = new JScrollPane(table);

        sorter = new TableRowSorter<>(scanTaskTableModel);
        table.setRowSorter(sorter);

        messageViewRootContainer = new JPanel(new BorderLayout());


        messageViewStyleSwitchPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));


        radioButtonContainer = new JPanel();
        radioButtonContainer.setLayout(new BoxLayout(radioButtonContainer, BoxLayout.LINE_AXIS));
        left2RightRadioButton = new JRadioButton("左右");
        top2DownRadioButton = new JRadioButton("上下");
        singleRadioButton = new JRadioButton("单图");
        radioButtonContainer.add(left2RightRadioButton);
        radioButtonContainer.add(top2DownRadioButton);
        radioButtonContainer.add(singleRadioButton);

        buttonGroup = new ButtonGroup();
        buttonGroup.add(left2RightRadioButton);
        buttonGroup.add(top2DownRadioButton);
        buttonGroup.add(singleRadioButton);
        left2RightRadioButton.setSelected(true);


        messageViewStyleSwitchPanel.add(radioButtonContainer);


        messageViewRootContainer.add(messageViewStyleSwitchPanel, BorderLayout.NORTH);


        messageViewPanelCardContainer = new JPanel();
        cardLayout = new CardLayout();
        messageViewPanelCardContainer.setLayout(cardLayout);

        requestMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), false);
        responseMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), false);

        doubleMessageView = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestMessageEditor.getComponent(), responseMessageEditor.getComponent());
        doubleMessageView.setResizeWeight(0.5);


        singleMessageView = new JTabbedPane();


        messageViewPanelCardContainer.add(doubleMessageView, DOUBLE_VIEW);
        messageViewPanelCardContainer.add(singleMessageView, SINGLE_VIEW);
//        cardLayout.show(messageViewPanelCardContainer, DOUBLE_VIEW);

        doubleMessageView.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
        doubleMessageView.setResizeWeight(0.5);
        doubleMessageView.setLeftComponent(requestMessageEditor.getComponent());
        doubleMessageView.setRightComponent(responseMessageEditor.getComponent());

        cardLayout.show(messageViewPanelCardContainer, DOUBLE_VIEW);
        messageShowStyle = MessageShowStyle.LEFT_2_RIGHT;


        messageViewRootContainer.add(messageViewPanelCardContainer);


        centerPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableContainer, messageViewRootContainer);
        centerPanel.setResizeWeight(0.6);


        add(centerPanel, BorderLayout.CENTER);


        southPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        statusInfoText = new JLabel("statusInfoText");
        southPanel.add(statusInfoText);

        add(southPanel, BorderLayout.SOUTH);

        initActionListeners();

    }

    private void initActionListeners() {
        left2RightRadioButton.addActionListener((ActionEvent e) -> {
            if (left2RightRadioButton.isSelected()) {
                doubleMessageView.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
                doubleMessageView.setResizeWeight(0.5);
                doubleMessageView.setLeftComponent(requestMessageEditor.getComponent());
                doubleMessageView.setRightComponent(responseMessageEditor.getComponent());
                messageShowStyle = MessageShowStyle.LEFT_2_RIGHT;

                cardLayout.show(messageViewPanelCardContainer, DOUBLE_VIEW);
            }
        });

        top2DownRadioButton.addActionListener(e -> {
            doubleMessageView.setOrientation(JSplitPane.VERTICAL_SPLIT);
            doubleMessageView.setResizeWeight(0.5);
            doubleMessageView.setTopComponent(requestMessageEditor.getComponent());
            doubleMessageView.setBottomComponent(responseMessageEditor.getComponent());
            messageShowStyle = MessageShowStyle.TOP_2_DOWN;

            cardLayout.show(messageViewPanelCardContainer, DOUBLE_VIEW);
        });

        singleRadioButton.addActionListener(e -> {
            singleMessageView.add(REQUEST, requestMessageEditor.getComponent());
            singleMessageView.add(RESPONSE, responseMessageEditor.getComponent());
            messageShowStyle = MessageShowStyle.SINGLE;

            cardLayout.show(messageViewPanelCardContainer, SINGLE_VIEW);
        });

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                super.mouseClicked(e);

                int mouseClickCnt = e.getClickCount();
                switch (mouseClickCnt) {
                    case 1:
                        tableMouseSingleClickEvent();
                        break;
                    case 2:
                        tableMouseDoubleClickEvent();
                        break;
                    default:
                        break;
                }


            }
        });

        scanTaskOperationBtnActionListeners();

    }

    private void filterTable() {
        if (0 == scanTaskTableModel.getRowCount()) {
            return;
        }

        Object selectedObject = filterColumnSelectionComboBox.getSelectedItem();
        String filterText = filterTextField.getText();

        if (null == filterText || filterText.isEmpty()) {
            sorter.setRowFilter(null);
            return;
        }
        if (null == selectedObject) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.NAME_INDEX));
            return;
        }

        if (selectedObject.equals(ScanTaskColumnName.ID.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.ID_INDEX));
        } else if (selectedObject.equals(ScanTaskColumnName.TASK_ID.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.TASK_ID_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.NAME.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.NAME_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.METHOD.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.METHOD_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.HOST.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.HOST_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.PORT.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.PORT_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.URL.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.URL_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.RESPONSE_STATUS_CODE.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.RESPONSE_STATUS_CODE_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.RESPONSE_CONTENT_LENGTH.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.RESPONSE_CONTENT_LENGTH_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.CMD_LINE.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.CMD_LINE_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.TASK_STATUS.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.TASK_STATUS_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.INJECTED.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.INJECTED_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.COMMENT.toString())) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.COMMENT_INDEX));

        } else {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.NAME_INDEX));

        }
    }

    private void scanTaskOperationBtnActionListeners() {
        filterBtn.addActionListener(e -> filterTable());

        startTaskBtn.addActionListener(e -> {
            int[] selectRows = table.getSelectedRows();
            if (null == selectRows || 0 == selectRows.length) {
                return;
            }

            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().lock();
            try {

                // 如果服务未运行退出
                if (SQLMAPAPI_SERVICE_STOP_FLAG) {
                    return;
                }
            } finally {
                SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().unlock();
            }

            SqlMapApiClient sqlMapApiClient = BurpExtender.getSqlMapApiClient();
            if (null == sqlMapApiClient) {
                return;
            }

            for (int selectRow : selectRows) {
                ScanTask scanTask = scanTaskTableModel.getScanTaskById(selectRow);
                if (null == scanTask || scanTask.getTaskStatus().equals(ScanTaskStatus.RUNNING) || scanTask.getTaskStatus().equals(ScanTaskStatus.ERROR)) {
                    continue;
                }

                try {
                    sqlMapApiClient.startScanTask(scanTask.getName(), scanTask.getCmdLine(), scanTask.getRequestResponse());
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }


            }
        });

        stopTaskBtn.addActionListener(e -> {
            int[] selectRows = table.getSelectedRows();
            if (null == selectRows || 0 == selectRows.length) {
                return;
            }

            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().lock();
            try {

                // 如果服务未运行退出
                if (SQLMAPAPI_SERVICE_STOP_FLAG) {
                    return;
                }
            } finally {
                SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().unlock();
            }

            SqlMapApiClient sqlMapApiClient = BurpExtender.getSqlMapApiClient();
            if (null == sqlMapApiClient) {
                return;
            }

            for (int selectRow : selectRows) {
                ScanTask scanTask = scanTaskTableModel.getScanTaskById(selectRow);
                if (null == scanTask || scanTask.getTaskStatus().equals(ScanTaskStatus.STOPPED) || scanTask.getTaskStatus().equals(ScanTaskStatus.ERROR)) {
                    continue;
                }

                Call call = sqlMapApiClient.stopScanTask(scanTask.getTaskId());
                call.enqueue(new Callback() {
                    @Override
                    public void onFailure(@NotNull Call call, @NotNull IOException e) {
                        BurpExtender.stderr.println(e.getMessage());
                    }

                    @Override
                    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                        ResponseBody responseBody = response.body();
                        if (null == responseBody) {
                            return;
                        }

                        String bodyStr = responseBody.string();
                        if (bodyStr.trim().isEmpty()) {
                            return;
                        }

                        ScanStopResponse scanStopResponse = JSON.parseObject(bodyStr, ScanStopResponse.class);
                        if (scanStopResponse.getSuccess()) {
                            scanTaskTableModel.updateScanTaskScanTaskStatusById(scanTask.getId(), ScanTaskStatus.STOPPED);
                        }

                    }
                });
            }


        });

        killTaskBtn.addActionListener(e -> {
            int[] selectRows = table.getSelectedRows();
            if (null == selectRows || 0 == selectRows.length) {
                return;
            }

            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().lock();
            try {

                // 如果服务未运行退出
                if (SQLMAPAPI_SERVICE_STOP_FLAG) {
                    return;
                }
            } finally {
                SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().unlock();
            }

            SqlMapApiClient sqlMapApiClient = BurpExtender.getSqlMapApiClient();
            if (null == sqlMapApiClient) {
                return;
            }

            for (int selectRow : selectRows) {
                ScanTask scanTask = scanTaskTableModel.getScanTaskById(selectRow);
                if (null == scanTask || scanTask.getTaskStatus().equals(ScanTaskStatus.STOPPED) || scanTask.getTaskStatus().equals(ScanTaskStatus.ERROR)) {
                    continue;
                }

                Call call = sqlMapApiClient.killScanTask(scanTask.getTaskId());
                call.enqueue(new Callback() {
                    @Override
                    public void onFailure(@NotNull Call call, @NotNull IOException e) {
                        BurpExtender.stderr.println(e.getMessage());
                    }

                    @Override
                    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                        ResponseBody responseBody = response.body();
                        if (null == responseBody) {
                            return;
                        }

                        String bodyStr = responseBody.string();
                        if (bodyStr.trim().isEmpty()) {
                            return;
                        }

                        ScanKillResponse scanKillResponse = JSON.parseObject(bodyStr, ScanKillResponse.class);
                        if (scanKillResponse.getSuccess()) {
                            scanTaskTableModel.updateScanTaskScanTaskStatusById(scanTask.getId(), ScanTaskStatus.KILLED);
                        }
                    }
                });
            }

        });

        deleteTaskBtn.addActionListener(e -> {
            int[] selectRows = table.getSelectedRows();
            if (null == selectRows || 0 == selectRows.length) {
                return;
            }

            SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().lock();
            try {

                // 如果服务未运行退出
                if (SQLMAPAPI_SERVICE_STOP_FLAG) {
                    return;
                }
            } finally {
                SQLMAPAPI_SERVICE_STOP_FLAG_LOCK.readLock().unlock();
            }

            SqlMapApiClient sqlMapApiClient = BurpExtender.getSqlMapApiClient();
            if (null == sqlMapApiClient) {
                return;
            }

            for (int selectRow : selectRows) {
                ScanTask scanTask = scanTaskTableModel.getScanTaskById(selectRow);

                Call call = sqlMapApiClient.deleteScanTask(scanTask.getTaskId());
                call.enqueue(new Callback() {
                    @Override
                    public void onFailure(@NotNull Call call, @NotNull IOException e) {
                        BurpExtender.stderr.println(e.getMessage());
                    }

                    @Override
                    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                        ResponseBody responseBody = response.body();
                        if (null == responseBody) {
                            return;
                        }

                        String bodyStr = responseBody.string();
                        if (bodyStr.trim().isEmpty()) {
                            return;
                        }

                        TaskDeleteResponse taskDeleteResponse = JSON.parseObject(bodyStr, TaskDeleteResponse.class);
                        if (taskDeleteResponse.getSuccess()) {
                            scanTaskTableModel.deleteScanTask(scanTask);
                        }
                    }
                });
            }
        });

        updateTaskBtn.addActionListener(e -> {
            int[] selectRows = table.getSelectedRows();
            if (null == selectRows || 1 != selectRows.length) {
                return;
            }

            ScanTask scanTask = scanTaskTableModel.getScanTaskById(selectRows[0]);
            if (null == scanTask) {
                return;
            }

            // 弹窗展示任务信息，进入编辑页面
            ScanTaskEditorDialog scanTaskEditorDialog = new ScanTaskEditorDialog(scanTask);
            scanTaskEditorDialog.setVisible(true);
        });

        selectAllBtn.addActionListener(e -> table.selectAll());

        selectNoneBtn.addActionListener(e -> table.clearSelection());
    }

    private void tableMouseSingleClickEvent() {
        int[] selectRows = table.getSelectedRows();
        if (null == selectRows || 0 == selectRows.length) {
            return;
        }

        ScanTask scanTask = scanTaskTableModel.getScanTaskById(selectRows[0]);

        IHttpRequestResponse httpRequestResponse = scanTask.getRequestResponse();
        if (null == httpRequestResponse) {
            return;
        }

        IMessageEditor requestMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), false);
        requestMessageEditor.setMessage(httpRequestResponse.getRequest(), true);
        setRequestMessageEditor(requestMessageEditor);


        byte[] httpResponseBytes = httpRequestResponse.getResponse();
        if (null == httpResponseBytes || 0 == httpResponseBytes.length) {
//                    httpRequestResponse.setResponse(new byte[]{});
            httpResponseBytes = new byte[]{};
//                    return;
        }

        IMessageEditor responseMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), false);
        responseMessageEditor.setMessage(httpResponseBytes, false);
        setResponseMessageEditor(responseMessageEditor);
    }

    private void tableMouseDoubleClickEvent() {
        int[] selectRows = table.getSelectedRows();
        if (null == selectRows || 1 != selectRows.length) {
            return;
        }

        ScanTask scanTask = scanTaskTableModel.getScanTaskById(selectRows[0]);
        ScanTaskStatus scanTaskStatus = scanTask.getTaskStatus();
        if (scanTaskStatus.equals(ScanTaskStatus.Not_STARTED)) {
            return;
        }

        ScanResultShowDialog scanResultShowDialog = new ScanResultShowDialog(scanTask.getTaskId());
        scanResultShowDialog.setVisible(true);

    }


    public void flushScanTaskStatus() {
        scanTaskTableModel.flushScanTaskStatus();
    }

    public int addNewScanTask(IHttpRequestResponse httpRequestResponse, String taskName, String taskId, String cmdLine) {
        if (null == httpRequestResponse || (null == taskName || taskName.trim().isEmpty()) || (null == taskId || taskId.trim().isEmpty())) {
            return -1;
        }
        if (null == cmdLine || cmdLine.trim().isEmpty()) {
            return -1;
        }

        ScanTask scanTask = new ScanTask();

        int id = scanTaskTableModel.getNewScanTaskId();
        scanTask.setId(id);

        scanTask.setName(taskName);

        scanTask.setRequestResponse(httpRequestResponse);

        byte[] requestBytes = httpRequestResponse.getRequest();
        if (null == requestBytes || 0 == requestBytes.length) {
            return -1;
        }

        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(httpRequestResponse);

        if (null == requestInfo) {
            return -1;
        }

        IHttpService httpService = httpRequestResponse.getHttpService();
        if (null == httpService) {
            return -1;
        }

        scanTask.setHost(httpService.getHost());
        scanTask.setPort(httpService.getPort());

        scanTask.setMethod(requestInfo.getMethod());
        URL url = requestInfo.getUrl();
        if (null == url) {
            return -1;
        }

        String urlStr;

        String query = requestInfo.getUrl().getQuery();
        if (null != query && 0 < query.length()) {
            urlStr = requestInfo.getUrl().getPath() + "?" + query;
        } else {
            urlStr = url.getPath();
        }

        scanTask.setUrl(urlStr);

        byte[] responseByte = httpRequestResponse.getResponse();
        if (null == responseByte || 0 == responseByte.length) {
            scanTask.setResponseStatusCode(-1);
            scanTask.setResponseContentLength(-1);

        } else {
            IResponseInfo responseInfo = BurpExtender.helpers.analyzeResponse(responseByte);
            scanTask.setResponseStatusCode(responseInfo.getStatusCode());
            scanTask.setResponseContentLength(responseByte.length);

        }


        scanTask.setTaskStatus(ScanTaskStatus.Not_STARTED);
        scanTask.setInjected(Injected.NOT_SURE);

        scanTask.setScanTaskResultDetail(new ScanTaskResultDetail());

        scanTask.setComment("");


        SwingUtilities.invokeLater(() -> scanTaskTableModel.AddNewScanTask(scanTask));

        return id;
    }

    public synchronized void setRequestMessageEditor(IMessageEditor messageEditor) {
        SwingUtilities.invokeLater(() -> {
            if (MessageShowStyle.LEFT_2_RIGHT == messageShowStyle) {
                doubleMessageView.setLeftComponent(messageEditor.getComponent());
            } else if (MessageShowStyle.TOP_2_DOWN == messageShowStyle) {
                doubleMessageView.setTopComponent(messageEditor.getComponent());
            } else if (MessageShowStyle.SINGLE == messageShowStyle) {
                singleMessageView.setComponentAt(0, messageEditor.getComponent());
            }
        });

        requestMessageEditor = messageEditor;

    }

    public synchronized void setResponseMessageEditor(IMessageEditor messageEditor) {
        SwingUtilities.invokeLater(() -> {
            if (MessageShowStyle.LEFT_2_RIGHT == messageShowStyle) {
                doubleMessageView.setRightComponent(messageEditor.getComponent());
            } else if (MessageShowStyle.TOP_2_DOWN == messageShowStyle) {
                doubleMessageView.setBottomComponent(messageEditor.getComponent());
            } else if (MessageShowStyle.SINGLE == messageShowStyle) {
                singleMessageView.setComponentAt(1, messageEditor.getComponent());
            }
        });

        responseMessageEditor = messageEditor;
    }

    public ScanTaskTableModel getScanTaskTableModel() {
        return scanTaskTableModel;
    }
}
