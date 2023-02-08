package com.metoo.nspm.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class TopoZoneDto {

    private Integer limit;
    private Integer page;
    private Object val;
    private String type;
    private Integer miitLevel;
    private String name;
    private String pUuid;
    private String remarks;
    private String uuid;
    private List zoneUuidList;
    private String zoneUuid;
    private String zoneSort;
    private String deviceUuid;
    private String businessZoneUuid;
    private List logicZoneDeviceEntityList;
    private List logicZoneSubnetEntityList;
    private String remark;
    private Integer sortId;
    private String zoneName;
    private Integer zoneStatus;
    private String zoneType;
    private String zoneUuids;
    private String pBusinessZoneUuid;
}
