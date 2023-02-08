package com.metoo.nspm.entity.Ipam;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class IpamAddress {

    private Long ipDetailId;
    private Integer id;
    private Integer subnetId;
    private String ip;
    private Boolean is_gateway;
    private String description;
    private String hostname;
    private String mac;
    private String owner;
    private Integer tag;
    private Boolean PTRignore;
    private Integer PTR;
    private Integer deviceId;
    private String port;
    private String note;
    private Date lastSeen;
    private Boolean excludePing;
    private Date editDate;
}
