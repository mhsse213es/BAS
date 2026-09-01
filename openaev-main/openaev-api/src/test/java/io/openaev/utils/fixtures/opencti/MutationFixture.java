package io.openaev.utils.fixtures.opencti;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.openaev.opencti.client.mutations.Mutation;

public class MutationFixture {
  public static class TestMutation implements Mutation {

    @Override
    public String getQueryText() {
      return "mutation test";
    }

    @Override
    public JsonNode getVariables() throws JsonProcessingException {
      return new ObjectMapper().createObjectNode();
    }
  }

  public static Mutation getDefaultMutation() {
    return new TestMutation();
  }
}
