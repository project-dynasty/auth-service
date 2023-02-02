package com.projectdynasty.models.permission;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;
import lombok.Getter;

@Table(name = "permission_groups")
@Getter
public class GroupData extends AbstractTable {

    @Column(name = "group_id")
    public long groupId;

    @Column(name = "group_name")
    public String groupName;

    @Column(name = "display_name")
    public String displayName;

    @Column(name = "department")
    public String department;

    @Column(name = "discord_permission_group_id")
    public Long discordPermissionGroupId;

    @Column(name = "team")
    public String team;

    @Column(name = "icon")
    public String icon;

    @Column(name = "type")
    public int type;

    @Column(name = "sort_id")
    public Integer sortId;

    public GroupData(Database database) {
        super(database);
    }
}
