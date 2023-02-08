package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@ApiModel("预置路径")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class PresetPath extends IdEntity {

        private String name;
        private Long topologyId;
        private String topologyName;
        private String content;
        private Long userId;
        private String userName;

        private String srcIp;
        private String srcMask;
        private String destIp;
        private String destMask;
}
