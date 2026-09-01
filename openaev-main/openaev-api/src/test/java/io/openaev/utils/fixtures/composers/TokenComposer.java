package io.openaev.utils.fixtures.composers;

import io.openaev.database.model.Token;
import io.openaev.database.repository.TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class TokenComposer extends ComposerBase<Token> {
  @Autowired private TokenRepository tokenRepository;

  public class Composer extends InnerComposerBase<Token> {
    private final Token token;

    public Composer(Token token) {
      this.token = token;
    }

    @Override
    public Composer persist() {
      tokenRepository.save(token);
      return this;
    }

    @Override
    public Composer delete() {
      tokenRepository.delete(token);
      return this;
    }

    @Override
    public Token get() {
      return this.token;
    }
  }

  public Composer forToken(Token token) {
    generatedItems.add(token);
    return new Composer(token);
  }
}
