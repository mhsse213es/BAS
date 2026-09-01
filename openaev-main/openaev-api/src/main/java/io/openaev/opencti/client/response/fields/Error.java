package io.openaev.opencti.client.response.fields;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import lombok.Data;

@Data
public class Error {
  @JsonProperty private String message;
  @JsonProperty private List<Location> locations;
  @JsonProperty private List<String> path;
}
