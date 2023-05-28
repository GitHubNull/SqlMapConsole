package entities;

public enum ScanTaskColumnName {
    ID("序号"), // 0

    TASK_ID("任务id"), // 1
    NAME("任务名"), // 2
    METHOD("方法"), // 3
    HOST("主机"), // 4
    PORT("端口"), // 5
    URL("链接"), // 6
    RESPONSE_STATUS_CODE("响应报文状态码"), // 7
    RESPONSE_CONTENT_LENGTH("响应报文长度"), // 8

    CMD_LINE("命令行参数"), //9

    TASK_STATUS("任务状态"), // 10
    INJECTED("是/否可注入"), // 11
    COMMENT("备注"); // 12

    private final String text;

    ScanTaskColumnName(final String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return text;
    }

}
