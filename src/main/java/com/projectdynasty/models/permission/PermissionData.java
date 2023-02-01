package com.projectdynasty.models.permission;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;
import lombok.Getter;

@Table(name = "user_permission")
@Getter
public class PermissionData extends AbstractTable {

    @Column(name = "user_id")
    private long userId;

    @Column(name = "permission_id")
    private long permissionId;

    @Column(name = "permission")
    private String permission;

    @Column(name = "negate")
    private boolean negate;

    @Column(name = "value")
    private int value;

    public PermissionData(Database database) {
        super(database);
    }
}
