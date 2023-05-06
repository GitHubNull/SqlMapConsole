package controller;

import burp.BurpExtender;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import ui.component.ScanTaskArgsHighConfigDialog;
import ui.component.ScanTaskArgsLowConfigDialog;
import ui.component.ScanTaskArgsMiddleConfigDialog;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuFactory implements IContextMenuFactory {
//    Set<Byte> allow_menu_in_set = new HashSet<>();

    public ContextMenuFactory() {
//        allow_menu_in_set.add(IContextMenuInvocation.)
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation contextMenuInvocation) {
        List<JMenuItem> menuItemList = new ArrayList<>();

        IHttpRequestResponse[] httpRequestResponses = contextMenuInvocation.getSelectedMessages();
        byte where_menu_in = contextMenuInvocation.getInvocationContext();


        if ((null == httpRequestResponses || 1 != httpRequestResponses.length)) {
            return menuItemList;
        }

        JMenuItem lowMenuItem = new JMenuItem("[低]新建扫描");
        JMenuItem middleMenuItem = new JMenuItem("[中]新建扫描");
        JMenuItem highMenuItem = new JMenuItem("[高]新建扫描");


        initActionListening(contextMenuInvocation, lowMenuItem, middleMenuItem, highMenuItem);
//        BurpExtender.stdout.println("ContextMenuFactory-->36, httpRequestResponses size: " + httpRequestResponses.length);


        menuItemList.add(lowMenuItem);
        menuItemList.add(middleMenuItem);
        menuItemList.add(highMenuItem);

        return menuItemList;
    }

    private void initActionListening(IContextMenuInvocation contextMenuInvocation, JMenuItem lowMenuItem, JMenuItem middleMenuItem, JMenuItem highMenuItem) {
        IHttpRequestResponse[] httpRequestResponses = contextMenuInvocation.getSelectedMessages();

        lowMenuItem.addActionListener(e -> {
            ScanTaskArgsLowConfigDialog scanTaskArgsLowConfigDialog = new ScanTaskArgsLowConfigDialog();
            scanTaskArgsLowConfigDialog.setScanTaskArgsList(BurpExtender.getScanTaskArgsList());
            scanTaskArgsLowConfigDialog.setVisible(true);
        });

        middleMenuItem.addActionListener(e -> {
            ScanTaskArgsMiddleConfigDialog scanTaskArgsMiddleConfigDialog = new ScanTaskArgsMiddleConfigDialog();
            scanTaskArgsMiddleConfigDialog.setScanTaskArgsList(BurpExtender.getScanTaskArgsList());
            scanTaskArgsMiddleConfigDialog.setVisible(true);
        });

        highMenuItem.addActionListener(e -> {
            ScanTaskArgsHighConfigDialog scanTaskArgsHighConfigDialog = new ScanTaskArgsHighConfigDialog(httpRequestResponses[0]);
            scanTaskArgsHighConfigDialog.setScanTaskArgsList(BurpExtender.getScanTaskArgsList());
            scanTaskArgsHighConfigDialog.setVisible(true);
        });
    }
}
