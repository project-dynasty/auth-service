package com.projectdynasty.payload.request;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class CreateChallengeRequest {

    private final String secret;

}
