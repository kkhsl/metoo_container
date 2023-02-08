package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class TopoNode extends IdEntity {

    private String branchLevel;
    private Long branchId;
    private String branchName;
    private String hostAddress;
    private String deviceName;
    private String vendorName;
    private String type;
    private Integer origin;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss",timezone="GMT+8")  //取日期时使用
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")//存日期时使用
    private Date gatherTime;
    private String skipAnalysis;
    private String toSameInbound;
    private String layerTwoDevice;
    private String description;
    private Integer state;
    private String uuid;
    private String vendorId;
    private Integer version;
    private String errorMess;
    private String stateDesc;
    private String charset;
    private String credentialUuid;
    private String pushCredentialUuid;
    private String taskType;
    private String taskUuid;
    private Integer timeout;
    private String webHref;
    private String modelNumber;
    private Long nodeId;
    private String gatherId;
    private Integer gatherType;
    private String ip;
}
