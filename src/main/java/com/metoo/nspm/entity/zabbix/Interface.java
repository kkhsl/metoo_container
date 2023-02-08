package com.metoo.nspm.entity.zabbix;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Interface {

    private Long hostid;
    private String ip;
    private String available;// 0 - (默认) 未知; 1 - 可用; 2 - 不可用。
    private String error;
}
