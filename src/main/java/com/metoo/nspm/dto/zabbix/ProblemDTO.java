package com.metoo.nspm.dto.zabbix;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("描述")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class ProblemDTO extends ParamsDTO  {

    private String ip;
    private List<String> hostids;
    private Object filter;
    private Integer limit;
    private String sortfield;
    private String sortorder;
    private String selectTags;
    private Long time_from;
    private Long time_till;
    private boolean recent;
}
