package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.DeviceConfig;
import com.metoo.nspm.entity.nspm.DeviceType;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ApiModel("设备类型")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class DeviceTypeDTO extends PageDto<DeviceType> {

    private String name;
    private Integer type;

}
