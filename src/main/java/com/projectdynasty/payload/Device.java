package com.projectdynasty.payload;

import com.projectdynasty.AuthService;
import com.projectdynasty.models.DeviceData;
import lombok.RequiredArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
public class Device {

    private final DeviceData data;

    public static Device get(int id) {
        DeviceData data = (DeviceData) AuthService.DATABASE.getTable(DeviceData.class).query().addParameter("device_id", id).executeOne();
        if (data == null)
            return null;
        return new Device(data);
    }

    public static List<Device> getFromUser(long userId) {
        List<Device> devices = new ArrayList<>();
        List<DeviceData> datas = AuthService.DATABASE.getTable(DeviceData.class).query().addParameter("user_id", userId).executeMany();
        if (datas != null && datas.size() > 0)
            datas.forEach(d -> devices.add(new Device(d)));
        return devices;
    }

    public static Device create(String address, String version, String type, String size, long userID) {
        DeviceData insert = AuthService.DATABASE.getTable(DeviceData.class);
        insert.ipAddress = address;
        insert.osType = type;
        insert.osVersion = version;
        insert.screenSize = size;
        insert.userId = userID;
        return get(insert.insert());
    }

    public long getId() {
        return data.deviceId;
    }

    public long getUserID() {
        return data.userId;
    }

    public String getToken() {
        return data.deviceToken;
    }

    public String getIpAddress() {
        return data.ipAddress;
    }

    public String getOsType() {
        return data.osType;
    }

    public String getOsVersion() {
        return data.osVersion;
    }

    public String getScreenSize() {
        return data.screenSize;
    }

}
