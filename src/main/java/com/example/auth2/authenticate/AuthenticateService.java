package com.example.auth2.authenticate;

import com.example.auth2.config.JwtTokenUtil;
import com.example.auth2.facebook.Facebook;
import com.example.auth2.facebook.FbAccessToken;
import com.example.auth2.facebook.Profile;
import com.example.auth2.model.JwtResponse;
import com.example.auth2.model.User;
import com.example.auth2.repo.UserRepository;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class AuthenticateService {

  private final UserRepository userRepository;
  private final JwtTokenUtil jwtTokenUtil;
  private final Facebook facebook;
  private final UserDetailsService userDetailsService;

  @Autowired
  public AuthenticateService(UserRepository userRepository, JwtTokenUtil jwtTokenUtil,
      Facebook facebook, UserDetailsService userDetails) {
    this.userRepository = userRepository;
    this.jwtTokenUtil = jwtTokenUtil;
    this.facebook = facebook;
    this.userDetailsService = userDetails;
  }

  public JwtResponse authenticateUser(FbAccessToken fbAccessToken) {
    Profile profile = facebook.getProfile(fbAccessToken.getToken());
    UserDetails userDetails = userDetailsService.loadUserByUsername(profile.getEmail());
    String token = jwtTokenUtil.generateToken(userDetails);
    return new JwtResponse(token);
  }
}
