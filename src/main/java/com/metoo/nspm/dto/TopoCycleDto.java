package com.metoo.nspm.dto;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("采集周期DTO")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class TopoCycleDto {

    private Integer id;
    private String ids;
    private Integer page;
    private Integer psize;

    private String cycleName;
    private String type;
    private Integer cycleType;
    private List updateCycleDTOS;
    private String branchLevel;
    private String week;
    private String day;
    private String hour;
    private String minute;
}
