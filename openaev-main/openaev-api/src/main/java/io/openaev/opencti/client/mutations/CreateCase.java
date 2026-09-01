package io.openaev.opencti.client.mutations;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CreateCase implements Mutation {
  private final String caseTitle;
  private final String caseDescription;

  private final String queryText =
      """
    mutation {
      caseIncidentAdd(
        input: {
          name: "%s",
          description: "%s"
         }
      )
      { id }
    }
    """;

  @Override
  public String getQueryText() {
    return this.queryText.formatted(this.caseTitle, this.caseDescription);
  }

  @Override
  public JsonNode getVariables() {
    return new ObjectMapper().valueToTree(Map.of());
  }
}
