package com.projectdynasty.payload.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class TwoFARequest {

    private final String code;
    private final String token;
    private boolean rememberMe;
    private boolean mobile;

}
