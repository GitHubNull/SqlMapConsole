package entities;

public enum ScanTaskColumnName {
    ID("序号"),
    NAME("任务名"),
    METHOD("方法"),
    HOST("主机"),
    PORT("端口"),
    URL("链接"),
    RESPONSE_STATUS_CODE("响应报文状态码"),
    RESPONSE_CONTENT_LENGTH("响应报文长度"),
    TASK_STATUS("任务状态"),
    INJECTED("是/否可注入"),
    COMMENT("备注");

    private final String text;

    ScanTaskColumnName(final String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return text;
    }

}
