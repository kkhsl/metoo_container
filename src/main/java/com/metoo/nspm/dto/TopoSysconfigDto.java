package com.metoo.nspm.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import javax.persistence.Access;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class TopoSysconfigDto {

    private Integer cid;
    private String ctype;
    private Integer status;
    private Integer objValue;
    private String unit;
    private String ipAddress;
}
