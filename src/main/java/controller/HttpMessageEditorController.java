package controller;

import burp.IHttpService;
import burp.IMessageEditorController;
import lombok.Data;

@Data
public class HttpMessageEditorController implements IMessageEditorController {
    private IHttpService httpService;
    private byte[] request;
    private byte[] response;

    public HttpMessageEditorController(IHttpService httpService, byte[] request, byte[] response) {
        this.httpService = httpService;
        this.request = request;
        this.response = response;
    }

    @Override
    public IHttpService getHttpService() {
        return null;
    }

    @Override
    public byte[] getRequest() {
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        return new byte[0];
    }
}
