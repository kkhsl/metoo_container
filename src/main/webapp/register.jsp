<%@ page contentType="text/html; charset=UTF-8" %>
<!DOCTYPE html>
<html lang="en">
<!--添加命名空间-->
<head>
    <meta charset="UTF-8">
    <title>shiro-注册页</title>

</head>
<body>
<h1>用户注册</h1>

<form action="${pageContext.request.contextPath}/user/register" method="post">
    用户名: <input type="text" name="username" id="username"/></br>
    密码: <input type="text" name="password" id="password"/></br>
    <input type="submit" value="用户注册"/>

</form>
</body>
</html>