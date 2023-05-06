package entities;

public enum ScanTaskStatus {
    Not_STARTED("未开始"),
    RUNNING("扫描中"),
    FINISHED("扫描完毕"),
    STOPPED("暂停"),
    ERROR("错误");

    private final String text;

    ScanTaskStatus(final String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return text;
    }
}
