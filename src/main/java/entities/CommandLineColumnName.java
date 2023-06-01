package entities;

public enum CommandLineColumnName {
    ID("序号"),
    WAS_DEFAULT("是否是默认参数"),
    TAG("标签"),

    COMMAND_LINE_STR("参数(s)字符串");

    private final String text;

    CommandLineColumnName(final String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return text;
    }
}
