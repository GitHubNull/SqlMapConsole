package entities;

public enum ScanTaskArgsColumnName {
    ID("序号"),
    TAG("标签"),
    ARGS_STR("参数(s)字符串");

    private final String text;

    ScanTaskArgsColumnName(final String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return text;
    }
}
