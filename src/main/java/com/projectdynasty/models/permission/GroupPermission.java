package com.projectdynasty.models.permission;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;
import lombok.Getter;

@Table(name = "group_permission")
@Getter
public class GroupPermission extends AbstractTable {

    @Column(name = "group_id")
    public long groupId;

    @Column(name = "permission_id")
    public long permissionId;

    @Column(name = "permission")
    public String permission;

    @Column(name = "negate")
    public boolean negate;

    @Column(name = "value")
    public int value;

    public GroupPermission(Database database) {
        super(database);
    }

}
