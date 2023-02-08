package com.metoo.nspm.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class ExposureDto {

    private Integer page;
    private Integer limit;
    private String tyoe;
}
