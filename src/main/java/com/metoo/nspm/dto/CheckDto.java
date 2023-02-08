package com.metoo.nspm.dto;

import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class CheckDto {

    private Integer checkStatus;
    private String deviceSearch;
    private Integer pageSize;
    private Integer currentPage;
    @ApiModelProperty("需要勾选的设备")
    private List<String> deviceUUIDs;
    private String recordId;

}
