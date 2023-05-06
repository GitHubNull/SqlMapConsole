package entities;

import lombok.Data;

@Data
public class ScanTaskArgs implements Comparable<ScanTaskArgs> {
    int id;
    String tag;
    String argsStr;

    public ScanTaskArgs(int id, String tag, String argsStr) {
        this.id = id;
        this.tag = tag;
        this.argsStr = argsStr;
    }


    @Override
    public int compareTo(ScanTaskArgs o) {
        Integer id = this.getId();
        return id.compareTo(o.getId());
    }
}
