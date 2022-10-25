package com.example.auth2.facebook;

import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;


@Component
public class Facebook {

  private static final String GRAPH_API_BASE_URL = "https://graph.facebook.com/v2.12";

  private final RestTemplate restTemplate;

  public Facebook(RestTemplate restTemplate) {
    this.restTemplate = restTemplate;
  }

  public Facebook getFacebook() {
    return new Facebook(new RestTemplate());
  }

  public Profile getProfile(String accessToken) {
    Profile profile = restTemplate.getForObject(
        GRAPH_API_BASE_URL + "/me?fields=email,name,id&access_token=" + accessToken
        , Profile.class);
    return profile;
  }
}
