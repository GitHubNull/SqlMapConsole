package controller;

import burp.IHttpService;
import burp.IMessageEditorController;

public class MessageEditorController implements IMessageEditorController {
    byte[] requestBytes;
    byte[] responseBytes;
    IHttpService httpService;


    public MessageEditorController() {
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public byte[] getRequest() {
        if (null == requestBytes || 0 == requestBytes.length) {
            return null;
        }
        return responseBytes;
    }

    @Override
    public byte[] getResponse() {
        if (null == responseBytes || 0 == responseBytes.length) {
            return null;
        }
        return responseBytes;
    }
}
