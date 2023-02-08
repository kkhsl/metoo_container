package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import javax.validation.constraints.Min;


@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class ThresholdDTO extends PageDto<ThresholdDTO> {
    @Min(message = "超过最小值", value = 0)
    private Double cpu;
    private Double memory;
    private Double flow;

}
