package com.projectdynasty.payload.request;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class SigninRequest {
    private final String username;
    private final String password;
    private final String osType, osVersion, screenSize;
    private final boolean rememberMe;
}
