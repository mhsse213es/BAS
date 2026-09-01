package io.openaev.opencti.errors;

public class ConnectorError extends Exception {
  public ConnectorError(String message) {
    super(message);
  }
}
