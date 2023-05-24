package sqlmapApi.responsesBody;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class VersionResponse {
    String version;
    Boolean success;
}
