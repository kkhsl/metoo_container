package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Subnet;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;


@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class SubnetDTO extends PageDto<Subnet> {

    private String subnet;
    private String mask;
    private String description;
    private Long masterSubnetId;

}
