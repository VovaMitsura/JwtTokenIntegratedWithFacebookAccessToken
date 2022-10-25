package com.example.auth2.model;

public class JwtResponse {

  private final String jwttoken;

  public JwtResponse(String jwttoken) {
    this.jwttoken = jwttoken;
  }

  public String getJwttoken() {
    return jwttoken;
  }
}

