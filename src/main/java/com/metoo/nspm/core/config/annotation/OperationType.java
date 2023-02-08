package com.metoo.nspm.core.config.annotation;

public enum OperationType {

    /**
     * 创建
     */
    CREATE,
    /**
     * 批量创建
     */
    BATCH_CREATE,
    /**
     * 更新
     */
    UPDATE,
    /**
     * 批量更新
     */
    BATCH_UPDATE,
    /**
     * 删除
     */
    DELETE,
    /**
     * 批量删除
     */
    BATCH_DELETE,
    /**
     * 导入
     */
    IMPORT,
    /**
     * 导出
     */
    EXPORT,
    /**
     * 其他类型
     */
    OTHER,
}
