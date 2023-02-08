package com.metoo.nspm.req;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("年级Req")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Accessors(chain = true)
public class GradeReq {

    private Long id;

    private Integer display;

    private Long Accessory;
}
