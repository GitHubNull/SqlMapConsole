package entities;

import lombok.Data;

@Data
public class ScanTaskOptionsCommandLine implements Comparable<ScanTaskOptionsCommandLine> {
    int id;
    String tag;
    String commandLineStr;

    public ScanTaskOptionsCommandLine(int id, String tag, String commandLineStr) {
        this.id = id;
        this.tag = tag;
        this.commandLineStr = commandLineStr;
    }


    @Override
    public int compareTo(ScanTaskOptionsCommandLine o) {
        Integer id = this.getId();
        return id.compareTo(o.getId());
    }
}
