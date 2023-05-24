package sqlmapApi.responsesBody;


import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
public class TaskNewResponse implements Serializable {
    String taskid;
    Boolean success;
}
