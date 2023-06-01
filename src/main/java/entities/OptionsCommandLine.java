package entities;

import lombok.Data;

import java.io.Serializable;

@Data
public class OptionsCommandLine implements Comparable<OptionsCommandLine>, Serializable {
    private final static long serialVersionUID = 1;
    int id;
    Boolean wasDefault;
    String tag;
    String commandLineStr;

    public OptionsCommandLine(int id, String tag, String commandLineStr, Boolean wasDefault) {
        this.id = id;
        this.wasDefault = wasDefault;
        this.tag = tag;
        this.commandLineStr = commandLineStr;
    }

    @Override
    public int compareTo(OptionsCommandLine o) {
        Integer id = this.getId();
        return id.compareTo(o.getId());
    }
}
