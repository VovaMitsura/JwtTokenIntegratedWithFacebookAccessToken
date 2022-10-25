package com.example.auth2.authenticate;

import com.example.auth2.facebook.Facebook;
import com.example.auth2.facebook.FbAccessToken;
import com.example.auth2.facebook.Profile;
import com.example.auth2.model.JwtResponse;
import com.example.auth2.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(produces = "application/json")
public class HomeController {

  private final AuthenticateService authenticateService;

  @Autowired
  public HomeController(AuthenticateService authenticateService) {
    this.authenticateService = authenticateService;
  }

  @PostMapping("/me")
  public ResponseEntity<JwtResponse> email(@RequestBody FbAccessToken accessToken) {
    JwtResponse jwtResponse = authenticateService.authenticateUser(accessToken);
    return ResponseEntity.ok(jwtResponse);
  }
}
