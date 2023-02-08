package com.metoo.nspm.entity.Ipam;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.Date;

@ApiModel("ipam子网管理")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class IpamSubnet {
    private Integer id;
    private String subnet;
    private Integer mask;
    private String description;
    private Integer sectionId;
    private Integer linked_subnet;
    private Integer vlanId;
    private Integer vrfId;
    private Integer masterSubnetId;
    private Integer nameserverId;
    private Boolean showName;
    private String permissions;
    private Boolean DNSrecursive;
    private Boolean DNSrecords;
    private Boolean allowRequests;
    private Boolean scanAgent;
    private Boolean pingSubnet;
    private Boolean discoverSubnet;
    private Boolean isFolder;
    private Boolean isFull;
    private Integer state;
    private Integer threshold;
    private Integer location;
    private Date editDate;



}
