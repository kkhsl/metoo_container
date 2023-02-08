package com.metoo.nspm.dto.zabbix;


import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("查询历史数据")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class HistoryDTO extends ParamsDTO {

    private Integer history;
    private List<Integer> hostids;
    private List<Integer> itemids;
    private Long time_from;
    private Long time_till;
    private Integer limit;
}
