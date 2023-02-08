package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class Task extends IdEntity {

    @ApiModelProperty("未开始")
    private Integer notStart;
    @ApiModelProperty("成功")// pushstatus 0：未开始 2：成功 3:失败
    private Integer finished;
    @ApiModelProperty("失败")
    private Integer failed;
    @ApiModelProperty("回滚成功")
    private Integer reverted;
    @ApiModelProperty("回滚失败")
    private Integer revertStatus;
    @ApiModelProperty("总数")
    private Integer total;
    @ApiModelProperty("工单类型")
    private Integer orderType;
    @ApiModelProperty("type 0：业务开通 1：策略优化 2：生成策略")
    private Integer type;
}
