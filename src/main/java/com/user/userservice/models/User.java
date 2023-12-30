package com.user.userservice.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Entity
public class User extends BaseModel{
    private String email;
    private String password;
    @ManyToMany
    @JoinTable(name = "User_role_mapping",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private List<Role> roles;
    @OneToMany(fetch = jakarta.persistence.FetchType.EAGER, mappedBy = "user")
    List<Session> sessions;
}
