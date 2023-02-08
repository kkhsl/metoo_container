<%@ page contentType="text/html; charset=UTF-8" %>
<%@taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>

<!DOCTYPE html>
<html lang="en">
<!--添加命名空间-->
<head>
    <meta charset="UTF-8">
    <title>shiro-首页</title>

</head>
<body>
<h1>系统主页V1.0</h1>
/*EL表达式：${pageContext.request.contextPath}*/
<a href="${pageContext.request.contextPath}/user/logout">退出</a>
<h1><shiro:principal/></h1>
<shiro:authenticated>认证后展示的内容</shiro:authenticated>
<shiro:notAuthenticated>未认证内容</shiro:notAuthenticated>
<ul>
    <shiro:hasRole name="BUYER_RETAIL">
        <li>零售管理
            <ul>
                <shiro:hasPermission name="BUYER_PUT">
                    <li>零售出库</li>
                </shiro:hasPermission>
                <shiro:hasPermission name="BUYER_RETURN">
                    <li>零售退货</li>
                </shiro:hasPermission>
            </ul>
        </li>
    </shiro:hasRole>
    <shiro:hasRole name="SELLER_PURCHASE">
        <li>采购管理
            <ul>
                <shiro:hasPermission name="SELLER_PUT">
                    <li>采购入库</li>
                </shiro:hasPermission>
                <shiro:hasPermission name="SELLER_RETURN">
                    <li>采购退货</li>
                </shiro:hasPermission>
            </ul>
        </li>
    </shiro:hasRole>
    <shiro:hasRole name="ADMIN_SELL">
        <li>销售管理
            <ul>
                <shiro:hasPermission name="ADMIN_SALE_ORDER">
                    <li>销售订单</li>
                </shiro:hasPermission>
                <shiro:hasPermission name="ADMIN_SALE_PUT">
                    <li>销售出库</li>
                </shiro:hasPermission>
                <shiro:hasPermission name="ADMIN_RETURN">
                    <li>销售退货</li>
                </shiro:hasPermission>


            </ul>
        </li>
    </shiro:hasRole>
    <shiro:hasRole name="ADMIN_STORE">
        <li>仓库管理
            <ul>
                <shiro:hasPermission name="COMBINED_ORDER">
                    <li>组装单</li>
                </shiro:hasPermission>
                <shiro:hasPermission name="REMOVE_ORDER">
                    <li>拆卸单</li>
                </shiro:hasPermission>
                <shiro:hasPermission name="OTHER_WAREHOUSE">
                <li>其他入库</li>
            </shiro:hasPermission>
            </ul>
        </li>
    </shiro:hasRole>
</ul>
</body>
</html>