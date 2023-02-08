package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("预置路径")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class TopoRoutesDTO<T> extends PageDto<TopoRoutesDTO> {

    private Integer start;
    private Integer limit;
    private String uuid;
    private String name;
    private String srcIp;
    private String dstIp;
    private int protocol;
    private String port;
    private String desc;
    private String content;
    private String layerUuid;
    private String layerName;
    private String ids;
    private String routeStr;
}
