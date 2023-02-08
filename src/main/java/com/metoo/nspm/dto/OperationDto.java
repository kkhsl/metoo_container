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
public class OperationDto<T> {

    private Integer limit;
    private Integer page;
    private Integer psize;
    private String userName;
    private Integer taskId;
    private String ids;
    private Integer pushStatus;
    private String action;
    private String beforeConflict;
    private String description;
    private String deviceUuid;
    private String dstIp;
    private String dstIpSystem;
    private String dstZone;
    private String inDevIf;
    private String inDevItfAlias;
    private String ipType;
    private String mergeCheck;
    private String outDevIf;
    private String outDevItf;
    private String outDevItfAlias;
    private String rangeFilter;
    private List serviceList;
    private String srcIp;
    private String srcIpSystem;
    private String srcZone;
    private String startTime;
    private String endTime;
    private String theme;
    private Integer type;
    private String isTrusted;
    private String isReload;
    private String status;
    private String protocol;
    private T disposalScenes;
    private String dstItf;
    private String inDevIfAlias;
    private String postIpAddress;
    private String postSrcIpSystem;
    private String srcItf;
    private String postPort;
    private String preIpAddress;
    private String prePort;
    private String dynamic;
    private String postDstIp;
    private String data;
    private String branchLevel;
    private Integer id;
    private String postDstIpSystem;
}

