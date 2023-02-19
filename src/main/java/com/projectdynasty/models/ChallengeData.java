package com.projectdynasty.models;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;

@Table(name = "challenge_data")
public class ChallengeData extends AbstractTable {

    @Column(autoIncrement = true, primaryKey = true)
    public int id;

    @Column
    public long user_id;

    @Column(length = 6)
    public String challenge;

    @Column(length = 32)
    public String status;

    @Column
    public long created;

    public ChallengeData(Database database) {
        super(database);
    }
}
