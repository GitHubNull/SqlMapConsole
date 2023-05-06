package entities;


import burp.IHttpRequestResponse;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OriginalRequestResponse implements Comparable<OriginalRequestResponse> {
    private final int id;
    private final IHttpRequestResponse requestResponse;
    private final String method;
    private final String host;
    private final String url;
    private final String infoText;
    private String comment = "";
    private final int statusCode;
    private final int responseContentLength;
//    private boolean marked = false;

    public OriginalRequestResponse(int id, IHttpRequestResponse requestResponse, String method, String host, String url, String infoText, int statusCode, int responseContentLength) {
        this.id = id;
        this.requestResponse = requestResponse;
        this.method = method;
        this.host = host;
        this.url = url;
        this.infoText = infoText;
        this.statusCode = statusCode;
        this.responseContentLength = responseContentLength;
    }


    @Override
    public int compareTo(OriginalRequestResponse o) {
        Integer id = this.getId();
        return id.compareTo(o.getId());
    }
}
