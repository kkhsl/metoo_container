package com.metoo.nspm.core.manager.admin.action;

public class ApiVersionController {

    /**
     * 1,利用用户自定义的request header
     * @RequestMapping(headers=apt-version=2)
     *
     * 2,利用URL
     * https://haveibeenpwned.com/api/v2/breachedaccount/foo
     *
     * 3,利用content type
     * Accept: application/vnd.haveibeenpwned.v2+json
     *
     * 4,利用content type
     * https://haveibeenpwned.com/api/breachedaccount/foo
     * Accept: application/vnd.haveibeenpwned+json; version=2.0
     * 这个方式和方式三的小不同的地方是，把版本号分离出来了
     *
     * 5,利用URL里的parameter
     * https://haveibeenpwned.com/api/breachedaccount/foo?v=2
     */

    /**
     * 使用名词、复数
     *
     * GET、POST、PUT、DELETE、HEAD、OPTIONS、PATCH、TRACE
     *
     * PUT:更新整个对象
     * PATCH:更新个别属性
     * HEAD:获取资源元数据；例如：一个资源的hash值、或者修改最后修改日期
     * OPTIONS:获得客户端针对一个资源能够实施的操作；（获得该资源的api（能够对资源做什么操作的描述））
     */
}
