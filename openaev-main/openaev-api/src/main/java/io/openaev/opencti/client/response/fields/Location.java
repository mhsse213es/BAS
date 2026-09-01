package io.openaev.opencti.client.response.fields;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class Location {
  @JsonProperty private int line;
  @JsonProperty private int column;
}
