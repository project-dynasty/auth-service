package com.projectdynasty.security.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@RequiredArgsConstructor
@Setter
@Getter
public class Token {

    private final String token;
    private final String refreshToken;
    private long id;

}
