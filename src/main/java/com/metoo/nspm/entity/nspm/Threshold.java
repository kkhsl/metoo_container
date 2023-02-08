package com.metoo.nspm.entity.nspm;


import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.math.BigDecimal;

@ApiModel("系统阈值")
@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class Threshold  extends IdEntity {

    private String cpu;
    private String memory;
    private String flow;
    private String globalmacroid;
    private Integer type; // 1: cpu 2：内存 3：流量
}
