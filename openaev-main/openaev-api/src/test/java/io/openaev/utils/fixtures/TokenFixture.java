package io.openaev.utils.fixtures;

import io.openaev.database.model.Token;
import java.time.Instant;

public class TokenFixture {
  public static Token getTokenWithValue(String value) {
    Token token = new Token();
    token.setValue(value);
    token.setCreated(Instant.now());
    return token;
  }
}
