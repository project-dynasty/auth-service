package com.projectdynasty.models.permission;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;

@Table(name = "group_permission")
public class GroupPermission extends AbstractTable {

    @Column(name = "group_id")
    private long groupId;

    @Column(name = "permission_id")
    private long permissionId;

    @Column(name = "permission")
    private String permission;

    @Column(name = "negate")
    private boolean negate;

    @Column(name = "value")
    private int value;

    public GroupPermission(Database database) {
        super(database);
    }

}
