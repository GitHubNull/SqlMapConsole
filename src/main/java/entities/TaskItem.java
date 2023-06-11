package entities;

import burp.IHttpRequestResponse;
import lombok.Data;


@Data
public class TaskItem {
    private String taskName;
    private String scanTaskCommandLineStr;
    private IHttpRequestResponse httpRequestResponse;

    public TaskItem(String taskName, String scanTaskCommandLineStr, IHttpRequestResponse httpRequestResponse) {
        this.taskName = taskName;
        this.scanTaskCommandLineStr = scanTaskCommandLineStr;
        this.httpRequestResponse = httpRequestResponse;
    }
}
