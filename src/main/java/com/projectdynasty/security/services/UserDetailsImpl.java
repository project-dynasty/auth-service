package com.projectdynasty.security.services;

import com.google.gson.Gson;
import com.projectdynasty.AuthService;
import com.projectdynasty.models.AccountData;
import com.projectdynasty.models.permission.GroupData;
import com.projectdynasty.models.permission.GroupPermission;
import com.projectdynasty.models.permission.PermissionData;
import com.projectdynasty.models.permission.UserGroupJoin;
import com.projectdynasty.payload.response.user.permission.PermissionResponse;
import de.alexanderwodarz.code.web.rest.authentication.Authentication;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.*;
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
    private Map<Long, Set<GroupPermission>> groupPermissions;

    public static UserDetailsImpl build(AccountData accountData) {

        List<PermissionData> userPermissions = AuthService.DATABASE.getTable(PermissionData.class).query().addParameter("user_id", accountData.userId).executeMany();
        List<UserGroupJoin> userGroupJoins = AuthService.DATABASE.getTable(UserGroupJoin.class).query().addParameter("user_id", accountData.userId).executeMany();
        List<GroupData> userGroups = new ArrayList<>();

        for (UserGroupJoin userGroupJoin : userGroupJoins) {
            GroupData groupData = (GroupData) AuthService.DATABASE.getTable(GroupData.class).query().addParameter("group_id", userGroupJoin.groupId).executeOne();
            if (groupData != null)
                userGroups.add(groupData);
        }

        Map<Long, Set<GroupPermission>> longSetMap = new HashMap<>();
        List<GroupPermission> groupPermissions = new ArrayList<>();
        for (GroupData groupData : userGroups) {
            groupPermissions.addAll(AuthService.DATABASE.getTable(GroupPermission.class).query().addParameter("group_id", groupData.groupId).executeMany());
            longSetMap.put(groupData.groupId, new HashSet<>(groupPermissions));
        }

        return new UserDetailsImpl(
                accountData.userId,
                accountData.username,
                accountData.firstName,
                accountData.lastName,
                accountData.disabled,
                new HashSet<>(userPermissions),
                new HashSet<>(userGroups),
                longSetMap
        );
    }

    public List<PermissionResponse> toPermissionResponse() {
        return permissions.stream().map(permission -> new PermissionResponse(permission.getPermission(), permission.isNegate(), permission.getValue())).collect(Collectors.toList());
    }

    public List<PermissionResponse> toGroupPermissionResponse(GroupData groupData) {
        return groupPermissions.get(groupData.groupId).stream().map(permission -> new PermissionResponse(permission.getPermission(), permission.isNegate(), permission.getValue())).collect(Collectors.toList());
    }
}
