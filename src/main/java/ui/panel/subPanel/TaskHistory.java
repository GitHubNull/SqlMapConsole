package ui.panel.subPanel;

import burp.*;
import controller.MessageEditorController;
import entities.Injected;
import entities.ScanTask;
import entities.ScanTaskResultDetail;
import entities.ScanTaskStatus;
import models.ScanTaskTableModel;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;

public class TaskHistory extends JPanel {
    JPanel northPanel;
    JTextField filterTextField;
    JButton filterBtn;

    JButton startTaskBtn;
    JButton stopTaskBtn;

    JButton deleteTaskBtn;

    JButton selectAllBtn;
    JButton selectNoneBtn;

    JSplitPane centerPanel;

    JScrollPane tableContainer;
    JTable table;
    ScanTaskTableModel scanTaskTableModel;


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

        filterTextField = new JTextField(32);
        filterBtn = new JButton("过滤");

        northPanel.add(filterTextField);
        northPanel.add(filterBtn);

        startTaskBtn = new JButton("开始扫描");
        stopTaskBtn = new JButton("停止扫描");

        deleteTaskBtn = new JButton("删除任务");

        selectAllBtn = new JButton("选择全部");
        selectNoneBtn = new JButton("全不选择");

        northPanel.add(startTaskBtn);
        northPanel.add(stopTaskBtn);

        northPanel.add(deleteTaskBtn);

        northPanel.add(selectAllBtn);
        northPanel.add(selectNoneBtn);

        add(northPanel, BorderLayout.NORTH);


        table = new JTable();
        table.setAlignmentX(JTable.LEFT_ALIGNMENT);
        scanTaskTableModel = new ScanTaskTableModel();
        table.setModel(scanTaskTableModel);
        tableContainer = new JScrollPane(table);


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

//        singleMessageView.add(new JLabel("singleMessageView"), BorderLayout.CENTER);

//        requestViewPanel = new JScrollPane();
//        responseViewPanel = new JScrollPane();

        requestMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), false);
        responseMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), false);

        doubleMessageView = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestMessageEditor.getComponent(), responseMessageEditor.getComponent());
        doubleMessageView.setResizeWeight(0.5);


        singleMessageView = new JTabbedPane();
//        singleMessageView.add(REQUEST, requestViewPanel);
//        singleMessageView.add(RESPONSE, responseViewPanel);


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
//                singleMessageView.setComponentAt(0, requestMessageEditor.getComponent());
//                singleMessageView.setComponentAt(1, responseMessageEditor.getComponent());
            singleMessageView.add(REQUEST, requestMessageEditor.getComponent());
            singleMessageView.add(RESPONSE, responseMessageEditor.getComponent());
            messageShowStyle = MessageShowStyle.SINGLE;

            cardLayout.show(messageViewPanelCardContainer, SINGLE_VIEW);
        });

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                super.mouseClicked(e);

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


                IMessageEditor responseMessageEditor = BurpExtender.callbacks.createMessageEditor(new MessageEditorController(), false);
                responseMessageEditor.setMessage(httpRequestResponse.getResponse(), false);
                setResponseMessageEditor(responseMessageEditor);
            }
        });

    }


    public void addNewScanTask(ScanTask scanTask) {
        scanTaskTableModel.AddNewScanTask(scanTask);
    }

    public void addNewScanTask(IHttpRequestResponse httpRequestResponse, String name) {
        if (null == httpRequestResponse || null == name) {
            return;
        }

        ScanTask scanTask = new ScanTask();

        int id = scanTaskTableModel.getNewScanTaskId();
        scanTask.setId(id);

        scanTask.setName(name);

        scanTask.setRequestResponse(httpRequestResponse);

        byte[] requestBytes = httpRequestResponse.getRequest();
        if (null == requestBytes || 0 == requestBytes.length) {
            return;
        }

        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(httpRequestResponse);

        if (null == requestInfo) {
            return;
        }

        IHttpService httpService = httpRequestResponse.getHttpService();
        if (null == httpService) {
            return;
        }

        scanTask.setHost(httpService.getHost());
        scanTask.setPort(httpService.getPort());

        scanTask.setMethod(requestInfo.getMethod());
        URL url = requestInfo.getUrl();
        if (null == url) {
            return;
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


        scanTaskTableModel.AddNewScanTask(scanTask);
    }

    public int getNewScanTaskId() {
        return scanTaskTableModel.getNewScanTaskId();
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

//        requestMessageEditor.setMessage(messageEditor.getMessage(), true);
//        requestViewPanel.setViewportView(requestMessageEditor.getComponent());
//        requestMessageEditor.setMessage(messageEditor.get);

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
//        responseMessageEditor.setMessage(messageEditor.getMessage(), false);
//        responseViewPanel.setViewportView(responseMessageEditor.getComponent());
    }
}
