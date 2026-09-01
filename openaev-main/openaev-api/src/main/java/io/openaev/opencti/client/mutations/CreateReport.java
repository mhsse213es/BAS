package io.openaev.opencti.client.mutations;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Map;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CreateReport implements Mutation {
  private final String reportTitle;
  private final String reportDescription;
  private final Instant reportPublishedAt;

  private final String queryText =
      """
    mutation {
      reportAdd(
        input: {
          name: "%s",
          description: "%s",
          published: "%s"
        }
      )
      { id }
    }
    """;

  @Override
  public String getQueryText() {
    return this.queryText.formatted(
        this.reportTitle, this.reportDescription, this.reportPublishedAt.toString());
  }

  @Override
  public JsonNode getVariables() {
    return new ObjectMapper().valueToTree(Map.of());
  }
}
