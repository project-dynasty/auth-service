package com.projectdynasty.payload.response.user.permission;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class PermissionResponse {

    private String permission;
    private boolean negate;
    private int value;

}
