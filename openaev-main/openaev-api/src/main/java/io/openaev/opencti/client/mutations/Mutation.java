package io.openaev.opencti.client.mutations;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;

public interface Mutation {
  String getQueryText();

  JsonNode getVariables() throws JsonProcessingException;
}
