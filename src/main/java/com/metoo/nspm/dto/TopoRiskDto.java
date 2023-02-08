package com.metoo.nspm.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class TopoRiskDto {

    private String id;
    private String ids;
    private String name;
    private String type;
    private String listType;
    private String recordId;
    private Integer page;
    private Integer limit;
    private String srcZoneUuid;
    private String dstZoneUuid;
    private String ruleType;
    private String isCheck;
    private String forcedStop;
    private String dstIpEnd;
    private String dstIpStart;
    private String dstPort;
    private String dstPortEnd;
    private String dstPortStart;
    private String dstPortType;
    private String dstSubnetText;
    private String dstSubnetUuid;
    private String protocol;
    private String remark;
    private String srcIpEnd;
    private String srcIpStart;
    private String srcSubnetText;
    private String srcSubnetUuid;
    private String dstIp;
    private String[] serviceList;
    private String srcIp;
    private Integer level;
    private String ruleId;
    private Integer currentPage;
    private Integer pageSize;
    private Integer objectType;
    private String objectName;
    private String objectInfo;
    private Integer sourceType;
    private String districtName;
    private String addressScope;
    private String identifier;
    private String srcDistrictId;
    private String districtUuid;
    private String dstDistrictId;

    private String ruleLevel;
    private String srcAddress;
    private String dstAddress;
    private String services;
    private String srcCheckType;
    private String dstCheckType;
    private String serviceCheckType;
    private String excludeSrcAddress;
    private String excludeDstAddress;
    private String excludeService;
    private String matrixSrcDistrictName;
    private String matrixDstDistrictName;
    private String matrixSrcAddress;
    private String matrixDstAddress;
}
