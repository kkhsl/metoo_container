package com.metoo.nspm.entity.nspm;


import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("策略统计")
public class PolicyStatistical extends IdEntity {

    private String code;
    private Double weight;
}
