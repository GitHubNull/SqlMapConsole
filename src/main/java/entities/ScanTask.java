package entities;

import burp.IHttpRequestResponse;
import lombok.Data;

@Data
public class ScanTask implements Comparable<ScanTask> {
    int id;
    String name;
    IHttpRequestResponse requestResponse;
    String method;
    String host;
    int port;
    String url;
    int responseStatusCode;
    int responseContentLength;


    ScanTaskStatus taskStatus;
    Injected injected;
    ScanTaskResultDetail scanTaskResultDetail;
    String comment;

    @Override
    public int compareTo(ScanTask o) {
        Integer id = this.getId();
        return id.compareTo(o.getId());
    }
}
