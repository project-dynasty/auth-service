package com.projectdynasty.security.services;

import com.google.gson.Gson;
import com.projectdynasty.AuthService;
import com.projectdynasty.models.AccountData;
import com.projectdynasty.models.permission.GroupData;
import com.projectdynasty.models.permission.PermissionData;
import com.projectdynasty.payload.response.user.permission.PermissionResponse;
import de.alexanderwodarz.code.web.rest.authentication.Authentication;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@AllArgsConstructor
public class UserDetailsImpl extends Authentication {

    private Long id;
    private String username;
    private String firstName;
    private String lastName;
    private boolean disabled;

    private Set<PermissionData> permissions;
    private Set<GroupData> roles;

    public static UserDetailsImpl build(AccountData accountData) {
        List<PermissionData> userPermissions = AuthService.DATABASE.getTable(PermissionData.class).query().addParameter("user_id", accountData.userId).executeMany();
        System.out.println(userPermissions);
        for (PermissionData userPermission : userPermissions) {
            System.out.println(userPermission.getPermission());
        }
        Set<PermissionData> permissionData = new HashSet<>(userPermissions);
        return new UserDetailsImpl(
                accountData.userId,
                accountData.username,
                accountData.firstName,
                accountData.lastName,
                accountData.disabled,
                new HashSet<>(userPermissions),
                new HashSet<>()
        );
    }

    public List<PermissionResponse> toPermissionResponse() {
        return permissions.stream().map(permission -> new PermissionResponse(permission.getPermission(), permission.isNegate(), permission.getValue())).collect(Collectors.toList());
    }

    public List<PermissionResponse> toGroupPermissionResponse(GroupData groupData) {
        return permissions.stream().map(permission -> new PermissionResponse(permission.getPermission(), permission.isNegate(), permission.getValue())).collect(Collectors.toList());
    }
}
