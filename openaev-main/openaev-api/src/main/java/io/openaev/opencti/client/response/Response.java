package io.openaev.opencti.client.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.List;
import lombok.*;

@Data
@NoArgsConstructor
public class Response {
  /*
   * Important note: a 2xx code on the HTTP request
   * does NOT imply a successfully run query
   * as per: https://graphql.org/learn/debug-errors/#graphql-errors-with-200-ok
   */
  private int status;

  @JsonProperty
  private List<io.openaev.opencti.client.response.fields.Error> errors = new ArrayList<>();

  @JsonProperty private ObjectNode data;

  public boolean isError() {
    return !this.getErrors().isEmpty();
  }
}
