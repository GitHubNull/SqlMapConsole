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

import static utils.GlobalStaticVariables.*;

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


    final static String REQUEST = EX_MSG.getMsg("request");
    final static String RESPONSE = EX_MSG.getMsg("response");


    JPanel messageViewRootContainer;

    JPanel messageViewStyleSwitchPanel;
    JPanel radioButtonContainer;

    ButtonGroup buttonGroup;
    JRadioButton left2RightRadioButton;
    JRadioButton top2DownRadioButton;
    JRadioButton singleRadioButton;

    JPanel messageViewPanelCardContainer;
    CardLayout cardLayout;

    final static String SINGLE_VIEW = EX_MSG.getMsg("single");
    final static String DOUBLE_VIEW = EX_MSG.getMsg("double");


    JTabbedPane singleMessageView;
//    JPanel doubleMessageView;

    JSplitPane doubleMessageView;

    //    JScrollPane requestViewPanel;
    IMessageEditor requestMessageEditor;

    //    JScrollPane responseViewPanel;
    IMessageEditor responseMessageEditor;

    JPanel southPanel;
    JTextPane statusInfoText;

    MessageShowStyle messageShowStyle;

    enum MessageShowStyle {
        LEFT_2_RIGHT, TOP_2_DOWN, SINGLE
    }

    public TaskHistory() {
        setLayout(new BorderLayout());

        northPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        filterLabel = new JLabel(EX_MSG.getMsg("by"));

        filterColumnSelectionComboBox = new JComboBox<>();
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("index"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("taskId"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("taskName"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("method"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("host"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("port"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("url"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("status_code"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("content_length"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("commandLine"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("task_status"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("injectionStatus"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("comment"));

        filterTextField = new JTextField(32);
        filterBtn = new JButton(EX_MSG.getMsg("filter"));

        northPanel.add(filterLabel);
        northPanel.add(filterColumnSelectionComboBox);
        northPanel.add(filterTextField);
        northPanel.add(filterBtn);

        startTaskBtn = new JButton(EX_MSG.getMsg("startScan"));
        stopTaskBtn = new JButton(EX_MSG.getMsg("stopScan"));
        killTaskBtn = new JButton(EX_MSG.getMsg("killScan"));

        deleteTaskBtn = new JButton(EX_MSG.getMsg("deleteTask"));
        updateTaskBtn = new JButton(EX_MSG.getMsg("updateTask"));

        selectAllBtn = new JButton(EX_MSG.getMsg("selectAll"));
        selectNoneBtn = new JButton(EX_MSG.getMsg("selectNone"));

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
        left2RightRadioButton = new JRadioButton(EX_MSG.getMsg("left2Right"));
        top2DownRadioButton = new JRadioButton(EX_MSG.getMsg("up2Down"));
        singleRadioButton = new JRadioButton(EX_MSG.getMsg("singleView"));
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


//        southPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        statusInfoText = new JTextPane();
        statusInfoText.setText(EX_MSG.getMsg("sqlMapApiStopped"));
//        southPanel.add(statusInfoText);

        add(statusInfoText, BorderLayout.SOUTH);

        initActionListeners();

    }

//    public void setStatusInfoTextStr(String statusStr){
//        statusInfoText.setText(statusStr);
//    }

    public JTextPane getStatusInfoText() {
        return statusInfoText;
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

        if (selectedObject.equals(ScanTaskColumnName.ID)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.ID_INDEX));
        } else if (selectedObject.equals(ScanTaskColumnName.TASK_ID)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.TASK_ID_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.NAME)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.NAME_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.METHOD)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.METHOD_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.HOST)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.HOST_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.PORT)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.PORT_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.URL)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.URL_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.RESPONSE_STATUS_CODE)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.RESPONSE_STATUS_CODE_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.RESPONSE_CONTENT_LENGTH)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.RESPONSE_CONTENT_LENGTH_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.CMD_LINE)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.CMD_LINE_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.TASK_STATUS)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.TASK_STATUS_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.INJECT_STATUS)) {
            sorter.setRowFilter(RowFilter.regexFilter(filterText, ScanTaskColumnNameIndex.INJECTED_INDEX));

        } else if (selectedObject.equals(ScanTaskColumnName.COMMENT)) {
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
                    scanTaskTableModel.updateScanTaskScanTaskStatusById(scanTask.getId(), ScanTaskStatus.NOT_STARTED);
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
                            response.close();
                            return;
                        }

                        String bodyStr = responseBody.string();
                        response.close();
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
                            response.close();
                            return;
                        }

                        String bodyStr = responseBody.string();
                        response.close();
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
                scanTaskTableModel.deleteScanTask(scanTask);

                Call call = sqlMapApiClient.deleteScanTask(scanTask.getTaskId());
                if (null == call) {
                    continue;
                }

                call.enqueue(new Callback() {
                    @Override
                    public void onFailure(@NotNull Call call, @NotNull IOException e) {
                        BurpExtender.stderr.println(e.getMessage());
                    }

                    @Override
                    public void onResponse(@NotNull Call call, @NotNull Response response) {
                        response.close();
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
        String scanTaskStatus = scanTask.getTaskStatus();
        if (scanTaskStatus.equals(ScanTaskStatus.NOT_STARTED)) {
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
        scanTask.setTaskId(taskId);

        scanTask.setName(taskName);
        scanTask.setCmdLine(cmdLine);

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


        scanTask.setTaskStatus(ScanTaskStatus.NOT_STARTED);
        scanTask.setInjectionStatus(InjectionStatus.NOT_SURE);

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

    public void updateI18n() {

        scanTaskTableModel.updateI18n();

        filterLabel.setText(EX_MSG.getMsg("by"));

        filterBtn.setText(EX_MSG.getMsg("filter"));

        startTaskBtn.setText(EX_MSG.getMsg("startScan"));
        stopTaskBtn.setText(EX_MSG.getMsg("stopScan"));
        killTaskBtn.setText(EX_MSG.getMsg("killScan"));

        deleteTaskBtn.setText(EX_MSG.getMsg("deleteTask"));
        updateTaskBtn.setText(EX_MSG.getMsg("updateTask"));

        selectAllBtn.setText(EX_MSG.getMsg("selectAll"));
        selectNoneBtn.setText(EX_MSG.getMsg("selectNone"));

        scanTaskTableModel.updateI18n();

        left2RightRadioButton.setText(EX_MSG.getMsg("left2Right"));
        top2DownRadioButton.setText(EX_MSG.getMsg("up2Down"));
        singleRadioButton.setText(EX_MSG.getMsg("singleView"));

        filterColumnSelectionComboBox.removeAllItems();
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("index"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("taskId"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("taskName"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("method"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("host"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("port"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("url"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("status_code"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("content_length"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("commandLine"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("task_status"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("injectionStatus"));
        filterColumnSelectionComboBox.addItem(EX_MSG.getMsg("comment"));
    }
}
