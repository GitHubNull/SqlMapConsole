package entities;

public enum Injected {
    YES("可注"),
    NO("不可"),
    NOT_SURE("未确定");

    private final String text;

    Injected(final String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return text;
    }
}
