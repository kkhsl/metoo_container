package com.metoo.nspm.entity.Ipam;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@ApiModel("ipam L2domain")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class IpamDomain {

    private Integer id;
    private Integer domainId;
    private String name;
    private Integer number;
    private String description;
    private Date editDate;

}
