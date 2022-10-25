package com.example.auth2.facebook;

public class FbAccessToken {
  private String token;

  public FbAccessToken(String token) {
    this.token = token;
  }

  public FbAccessToken() {
  }

  public String getToken() {
    return token;
  }

  public void setToken(String token) {
    this.token = token;
  }
}
