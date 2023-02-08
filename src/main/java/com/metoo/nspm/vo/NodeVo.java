package com.metoo.nspm.vo;

import com.metoo.nspm.dto.page.PageDto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class NodeVo extends PageDto<NodeVo> {

    private String branchLevel;
    private String changeFlog;
    private String changeStatus;
    private String charset;
    private String controllerId;
    private String createdTime;
    private String credentialUuid;
    private String customPythonPath;
    private String description;
    private String deviceLogUuid;
    private String deviceName;
    private String deviceTemplateId;
    private String errorMess;
    private String filePath;
    private String gatherCycle;
    private String gatherId;
    private String gatherTime;
    private String gatherType;
    private String historyId;
    private String id;
    private String includeRouting;
    private String ip;
    private String isChangeWarn;
    private String logConfigStatus;
    private String modelNumber;
    private String modifiedTime;
    private String nodeGroup;
    private String nodeGroupName;
    private String origin;
    private String pluginId;
    private String portNumber;
    private String state;
    private String stateDesc;
    private String taskType;
    private String taskUuid;
    private String timeout;
    private String type;
    private String uuid;
    private String vSysName;
    private String vendorId;
    private String vendorName;
    private String version;
    private String webHref;
    private String webUrl;





}
