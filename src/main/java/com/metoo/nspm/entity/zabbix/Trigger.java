package com.metoo.nspm.entity.zabbix;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Trigger {

    private String description;
    private String expression;
    private Integer recovery_mode;
    private String recovery_expression;
}
