package com.projectdynasty.models.permission;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;

@Table(name = "user_group_join")
public class UserGroupJoin extends AbstractTable {

    @Column(name = "user_id")
    public long userId;
    @Column(name = "group_id")
    public long groupId;

    public UserGroupJoin(Database database) {
        super(database);
    }
}
