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
    public long userId;

    @Column(name = "permission_id")
    public long permissionId;

    @Column(name = "permission")
    public String permission;

    @Column(name = "negate")
    public boolean negate;

    @Column(name = "value")
    public int value;

    public PermissionData(Database database) {
        super(database);
    }
}
