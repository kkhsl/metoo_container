package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class PlantRoomDTO extends PageDto<PlantRoomDTO> {

    private Long id;
    private Date addTime;
    @ApiModelProperty("名称")
    private String name;
    @ApiModelProperty("描述")
    private String description;
    @ApiModelProperty("用户")
    private Long userId;

}
