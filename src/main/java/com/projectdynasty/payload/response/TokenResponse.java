package com.projectdynasty.payload.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@RequiredArgsConstructor
@Setter
@Getter
public class TokenResponse {

    private final String token;
    private final String refreshToken;
    private long id;

}
