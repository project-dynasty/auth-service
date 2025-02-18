package com.projectdynasty.security;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthStatus {

    private String token, status;
    private long id, deviceId;
    private int mobileConfirm, fakeOne, fakeTwo;
    private boolean rememberMe, mobile = false;

}
