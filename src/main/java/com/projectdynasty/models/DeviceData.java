package com.projectdynasty.models;

import de.alexanderwodarz.code.database.AbstractTable;
import de.alexanderwodarz.code.database.Database;
import de.alexanderwodarz.code.database.annotation.Column;
import de.alexanderwodarz.code.database.annotation.Table;

@Table(name = "device_data")
public class DeviceData extends AbstractTable {

    @Column(autoIncrement = true, primaryKey = true, name = "device_id")
    public long device_id;

    @Column(length = 255, name = "device_token")
    public String deviceToken;

    @Column(length = 255, name = "ip_address")
    public String ipAddress;

    @Column(length = 255, name = "os_type")
    public String osType;

    @Column(length = 255, name = "os_version")
    public String osVersion;

    @Column(length = 255, name = "screen_size")
    public String screenSize;

    @Column(name = "user_id")
    public long user_id;

    public DeviceData(Database database) {
        super(database);
    }
}
