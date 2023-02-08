package com.metoo.nspm.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.io.Serializable;
import java.util.Date;
import java.util.List;


@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class TopoPolicyDto implements Serializable {

    private Date addTime;
    private Integer origin;
    private String id;
    private String ids;
    private Integer start;
    private Integer currentPage;
    private Integer pageSize;
    private String vendor;
    private String type;
    private Integer display;
    private String deviceUuid;
    private String layerUuid;
    private String isFilter;
    private String policyListUuid;
    private String filter;
    private String zoneUuid;
    private String objectType;
    private List ruleUuidList;
    private String skip;
    private String name;
    private String nodeIp;
    private String policyId;
    private String policyName;
    private String ruleListName;
    private String policyType;
    private String createUser;
    private String remarks;
    private String expireTime;
    private String ruleField;
    private String ruleUuid;
    private List<Object> tasks;
    private String vendorName;
    private Integer page;
    private Integer limit;
    private String ipRanges;
    private String typeStatus;
    private String devId;
    private String devIp;
    private String typeId;
    private String logCenterEnabled;
    private String logCenterIp;
    private String logCenterUniqueName;
    private String haEnabled;
    private String timeType;
    private String startTime;
    private String endTime;
    private String policyIds;
    private String policyUuid;
    private String splicingPrimary;
    private String flag;
    private String taskName;
    private String devName;
    private String inbound;
    private String srcIp;
    private String dstIp;
    private String filterService;
    private String filterSrcIp;
    private String filterDstIp;
    private String isGather;
    private String gatherObj;
    private String gatherMaskBit;
    private String isInternet;
    private String taskIds;
    private Integer taskId;
    private String slaveDeviceUuid;
    private String masterDeviceUuid;
    private String jsonQuery;
    private String content;
    private String searchType;
    private Integer dstPortStart;
    private Integer dstPortEnd;
    private Integer protocol;
    private String userName;

    private Integer status;
    private Integer psize = 100000;
    private String theme;
    private String dstPort;
    private String batchId;
    private String description;

    private String beforeConflict;
    private String dstIpSystem;
    private String ipType;
    private String labelModel;
    private String mergeCheck;
    private String postDstIp;
    private String postSrcIp;
    private List serviceList;
    private String srcIpSystem;
    private String startLabel;
    private Integer taskType;

    private String isTrusted;
    private String isReload;
    private Integer pathInfoId;
    private String pathInfoIds;
    private Integer enable;
    private String isVerifyData;
    private String isRevert;
    private String schedule;
    private String enableEmail;
    private String receiverEmail;
    private String inDevIf;

    private Integer pageNum;
    private Integer pushStatus;
    private Integer revertStatus;

    private String deviceName;
    private String command;
    private String orderNo;
    private Integer pathIndex;
    private String branchLevel;

    private String inDevItfAlias;
    private String relevancyNat;
    private String idleTimeout;
    private String from;
    private String grade;
    private String skipAny;
    private String isQueryParams;
    private String ipTerms;
    private String state;
    private Integer index;
    private String nextHop;

    private Integer ipLength;
    private Integer ipLengthes;
    private String dstMask;
    private Object policyDetailVO;
    private Object policyHitEntity;
    private String srcMask;
    private String srcZone;
    private String dstZone;
    private String characterSet;
    private String interfaceIp;
    private String interfaceName;
    private String haDevIds;
    private String devAlias;
    private String rawSrcIp;
    private String rawDstIp;
    private String srcPort;
    private String obj2;
    private String obj3;
    private String outbound;
    private String queryStrDevIp;
}
