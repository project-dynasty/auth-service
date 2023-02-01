package com.projectdynasty.models.permission;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;
import lombok.Getter;

@Getter
@Table(name = "permission_groups")
public class GroupData extends AbstractTable {

    @Column(name = "group_id")
    private long groupId;

    @Column(name = "group_name")
    private String name;

    @Column(name = "display_name")
    private String displayName;

    @Column(name = "department")
    private String department;

    @Column(name = "discord_permission_group_id")
    private Long discordPermissionGroupId;

    @Column(name = "team")
    private String team;

    @Column(name = "icon")
    private String icon;

    @Column(name = "type")
    private int type;

    @Column(name = "sort_id")
    private Integer sortId;

    public GroupData(Database database) {
        super(database);
    }
}
