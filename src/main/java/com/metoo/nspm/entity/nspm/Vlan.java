package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;

@ApiModel("Virtual Local Area Network")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class Vlan extends IdEntity {

    private String name;
    private int number;
    private String description;
    private Date editDate;
    private Long groupId;
    private Long domainId;
    private String domainName;
    @ApiModelProperty("所属子网/网段")
    private String subnet;
}
