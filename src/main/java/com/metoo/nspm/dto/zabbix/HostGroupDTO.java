package com.metoo.nspm.dto.zabbix;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class HostGroupDTO extends ParamsDTO {

    private List<String> name;
    private Object filter;

}
