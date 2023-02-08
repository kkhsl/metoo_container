package com.metoo.nspm.entity.zabbix;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class History {

    private Long itemid;
    private Long clock;
    private String time;
    private double value;
    private Integer ns;
}
