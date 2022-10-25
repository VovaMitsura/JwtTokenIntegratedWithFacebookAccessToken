package com.example.auth2.model;

import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * User entity for Spring JPA.
 */
@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class User {

  @Id
  private String email;
  @Enumerated(EnumType.STRING)
  private UserRole role;

  /**
   * User Role enum.
   */
  public enum UserRole{
    INTERVIEWER,
    COORDINATOR,
    CANDIDATE
  }
}
